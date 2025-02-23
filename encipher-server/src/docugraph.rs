use anyhow::{Context, Result};
use indradb::{
    BulkInsertItem, Database, Edge, Identifier, Json, RocksdbDatastore, Vertex, VertexProperty,
};
use ndarray::{Array1, ArrayView1};
use ollama_rs::{error::OllamaError, generation::completion::request::GenerationRequest, Ollama};
use rust_bert::{
    pipelines::{
        sentence_embeddings::{
            SentenceEmbeddingsConfig, SentenceEmbeddingsModel, SentenceEmbeddingsModelType,
        },
        sequence_classification::Label,
        zero_shot_classification::ZeroShotClassificationModel,
    },
    RustBertError,
};
use std::{collections::HashMap, path::Path};
use tokio::task;

const SIMILARITY_THRESHOLD: f32 = 0.7;
const TOP_K: usize = 5;

#[derive(Debug, Clone)]
struct Document {
    id: uuid::Uuid,
    // `text` here is the summary (or combined text) stored in the graph.
    text: String,
    embedding: Vec<f32>,
    // Record the original index so we can link back to the original plaintext.
    original_index: Option<usize>,
}

pub struct GraphRAGSystem {
    db: Database<RocksdbDatastore>,
    embedding_model: SentenceEmbeddingsModel,
    documents: HashMap<uuid::Uuid, Document>,
}

impl GraphRAGSystem {
    // Make new() async to offload blocking creation of RocksDB.
    pub async fn new(path: &str) -> Result<Self> {
        let embedding_model_config: SentenceEmbeddingsConfig =
            SentenceEmbeddingsConfig::from(SentenceEmbeddingsModelType::AllMiniLmL12V2);
        let path = path.to_string();
        let db = task::spawn_blocking(move || RocksdbDatastore::new_db(&path)).await??;
        let embedding_model = task::spawn_blocking(move || SentenceEmbeddingsModel::new(embedding_model_config))
            .await?
            .context("Failed to initialize embedding model")?;
        Ok(Self {
            db,
            embedding_model,
            documents: HashMap::new(),
        })
    }

    /// Build similarity graph by connecting documents with similarity above threshold.
    pub fn build_similarity_graph(&mut self) -> Result<()> {
        let mut edges = Vec::new();
        let doc_ids: Vec<uuid::Uuid> = self.documents.keys().cloned().collect();

        for (i, id1) in doc_ids.iter().enumerate() {
            let doc1 = &self.documents[id1];

            for id2 in doc_ids.iter().skip(i + 1) {
                let doc2 = &self.documents[id2];

                let similarity = cosine_similarity(
                    ArrayView1::from(&doc1.embedding),
                    ArrayView1::from(&doc2.embedding),
                );

                if similarity > SIMILARITY_THRESHOLD {
                    edges.push(BulkInsertItem::Edge(Edge::new(
                        *id1,
                        Identifier::new("similar_to")?,
                        *id2,
                    )));
                    edges.push(BulkInsertItem::EdgeProperty(
                        Edge::new(*id1, Identifier::new("similar_to")?, *id2),
                        Identifier::new("similarity")?,
                        Json::new(serde_json::json!(similarity)),
                    ));
                }
            }
        }

        self.db.bulk_insert(edges)?;
        Ok(())
    }

    /// Process and store documents with embeddings.
    /// `texts` here are the combined texts (e.g. name + summary) that are stored in the graph.
    /// The optional `indices` parameter records the original index.
    pub fn process_documents(&mut self, texts: &[String], indices: Option<&[usize]>) -> Result<()> {
        let embeddings = self
            .embedding_model
            .encode(texts)
            .context("Failed to generate embeddings")?;

        let mut bulk_insert = Vec::new();

        for (idx, (text, embedding)) in texts.iter().zip(embeddings.iter()).enumerate() {
            let original_index = indices.and_then(|inds| inds.get(idx).copied());
            let doc = Document {
                id: uuid::Uuid::new_v4(),
                text: text.clone(),
                embedding: embedding.clone(),
                original_index,
            };

            bulk_insert.push(BulkInsertItem::Vertex(Vertex::with_id(
                doc.id,
                Identifier::new("document")?,
            )));

            bulk_insert.push(BulkInsertItem::VertexProperty(
                doc.id,
                Identifier::new("text")?,
                Json::new(serde_json::json!(doc.text)),
            ));

            bulk_insert.push(BulkInsertItem::VertexProperty(
                doc.id,
                Identifier::new("embedding")?,
                Json::new(serde_json::json!(doc.embedding)),
            ));

            if let Some(idx_val) = original_index {
                bulk_insert.push(BulkInsertItem::VertexProperty(
                    doc.id,
                    Identifier::new("original_index")?,
                    Json::new(serde_json::json!(idx_val)),
                ));
            }

            self.documents.insert(doc.id, doc);
        }

        self.db
            .bulk_insert(bulk_insert)
            .context("Failed to bulk insert documents")
    }

    /// Query the graph with a prompt and return the top K documents (as references) with their similarity scores.
    pub fn query(&self, prompt: &str) -> Result<Vec<(&Document, f32)>> {
        let prompt_embedding = self
            .embedding_model
            .encode(&[prompt.to_string()])
            .context("Failed to generate prompt embedding")?
            .remove(0);

        let prompt_vector = ArrayView1::from(&prompt_embedding);

        let mut similarities: Vec<(&Document, f32)> = self
            .documents
            .values()
            .map(|doc| {
                let doc_vector = ArrayView1::from(&doc.embedding);
                (doc, cosine_similarity(prompt_vector, doc_vector))
            })
            .collect();

        similarities.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        Ok(similarities.into_iter().take(TOP_K).collect())
    }
}

/// Cosine similarity calculation using ndarray.
fn cosine_similarity(a: ArrayView1<f32>, b: ArrayView1<f32>) -> f32 {
    let dot_product = a.dot(&b);
    let norm_a = a.dot(&a).sqrt();
    let norm_b = b.dot(&b).sqrt();
    dot_product / (norm_a * norm_b + f32::EPSILON)
}

pub fn zero_shot_classification_single(
    prompt: &str,
    tags: &[&str],
) -> Result<Vec<Vec<Label>>, RustBertError> {
    let sequence_classification_model = ZeroShotClassificationModel::new(Default::default())?;
    sequence_classification_model.predict_multilabel(&[prompt], tags, None, usize::MAX)
}

/// GraphRAGManager encapsulates multiple GraphRAGSystem instances along with a mapping of original texts.
pub struct GraphRAGManager {
    // Keyed by (classification, tag)
    systems: HashMap<(String, String), GraphRAGSystem>,
    // Mapping from original document index to its plaintext.
    original_texts: HashMap<usize, String>,
}

impl GraphRAGManager {
    /// Constructs and populates the manager by creating a GraphRAGSystem for each (classification, tag)
    /// combination, processing the provided documents, and storing the original document texts.
    pub async fn new(
        classification_levels: Vec<String>,
        team_name: String,
        tags: Vec<String>,
        names: Vec<String>,
        document_classifications: Vec<String>,
        documents: Vec<String>,
    ) -> Result<Self> {
        let mut systems = HashMap::new();
        let mut original_texts = HashMap::new();

        // Create a system for each classification-tag pair.
        for classification in &classification_levels {
            for tag in &tags {
                let db_name = format!("{}-{}-{}", team_name, classification, tag);
                let graph_rag = GraphRAGSystem::new(&db_name).await?;
                systems.insert((classification.clone(), tag.clone()), graph_rag);
            }
        }

        // Process each document; record the original index and store the original text.
        for (i, ((name, document), doc_classification)) in names
            .into_iter()
            .zip(documents.into_iter())
            .zip(document_classifications.into_iter())
            .enumerate()
        {
            // Save the original document text.
            original_texts.insert(i, document.clone());

            // Generate a summary (and combine with the document name) for graph ingestion.
            let summary = summarize_doc(&document).await?;
            let combined_text = format!("{}\n{}", name, summary);

            // For each system matching the document's classification, check if the tag applies.
            for ((classification, tag), system) in systems.iter_mut() {
                if doc_classification == *classification {
                    match zero_shot_classification_single(&combined_text, &[tag.as_str()]) {
                        Ok(results) => {
                            if results[0][0].text == *tag {
                                // Process this document into the system and record its original index.
                                system.process_documents(&[combined_text.clone()], Some(&[i]))?;
                            }
                        }
                        Err(e) => {
                            eprintln!("Error during zero-shot classification: {}", e);
                            continue;
                        }
                    }
                }
            }
        }

        Ok(Self {
            systems,
            original_texts,
        })
    }

    /// Determines the best tag for the given prompt (using zero-shot classification) and
    /// queries the corresponding GraphRAGSystem. It then recovers the original document plaintext
    /// using the stored indices and builds a prompt to send to Ollama.
    pub async fn query_by_prompt(
        &self,
        classification: &str,
        candidate_tags: &[String],
        prompt: &str,
    ) -> Result<String> {
        let tags_slice: Vec<&str> = candidate_tags.iter().map(|s| s.as_str()).collect();
        let results = zero_shot_classification_single(prompt, &tags_slice)
            .map_err(|e| anyhow::anyhow!("Zero-shot classification error: {}", e))?;
        let best_tag = &results[0][0].text;

        if let Some(system) = self
            .systems
            .get(&(classification.to_string(), best_tag.to_string()))
        {
            let top_results = system.query(prompt)?;
            let mut combined_texts = String::new();
            for (doc, _sim) in top_results {
                if let Some(idx) = doc.original_index {
                    if let Some(original_text) = self.original_texts.get(&idx) {
                        combined_texts.push_str(original_text);
                    } else {
                        combined_texts.push_str(&doc.text);
                    }
                } else {
                    combined_texts.push_str(&doc.text);
                }
                combined_texts.push_str("\n\n---\n\n");
            }
            let prompt_for_ollama = format!(
                "Based on the following original documents:\n\n{}\n\nPlease provide a detailed and accurate answer to the query: '{}'",
                combined_texts, prompt
            );
            let ollama = Ollama::new("http://ollama".to_string(), 11434);
            let generation_request =
                GenerationRequest::new("deepseek-r1:1.5b".to_string(), prompt_for_ollama);
            let response = ollama.generate(generation_request).await?;
            Ok(response.response.trim().to_string())
        } else {
            Err(anyhow::anyhow!(
                "No system found for classification '{}' and tag '{}'",
                classification,
                best_tag
            ))
        }
    }
}

pub async fn summarize_doc(doc: &str) -> Result<String, OllamaError> {
    let ollama = Ollama::new("http://ollama".to_string(), 11434);
    let initial_prompt = include_str!("static.initial_prompt.txt");
    let full_prompt = format!("{} <document>{}</document>", initial_prompt, doc);
    let response = ollama
        .generate(GenerationRequest::new(
            "deepseek-r1:1.5b".to_string(),
            full_prompt,
        ))
        .await?
        .response;
    Ok(response.trim_start_matches("</think>").trim().to_string())
}

use rand::rng;
use rand::seq::{IndexedRandom, SliceRandom};
use std::thread;
use tokio::runtime::Builder;

pub async fn run_graph_rag_manager_random_classification() -> Result<()> {
    tracing::info!("Starting random classification test");
    
    // Set up classification types.
    let classification_levels = vec![
        "public".to_string(),
        "private".to_string(),
        "internal".to_string(),
    ];
    tracing::debug!("Classification levels: {:?}", classification_levels);
    
    let team_name = "RandomTeam".to_string();
    // Candidate tags for each system.
    let tags = vec![
        "science".to_string(),
        "tech".to_string(),
        "history".to_string(),
    ];
    tracing::debug!("Tags: {:?}", tags);

    let mut names = Vec::new();
    let mut document_classifications = Vec::new();
    let mut documents = Vec::new();

    let mut rng = rand::rng();

    tracing::info!("Generating 50 random test documents");
    // Generate 50 documents with random classifications and topics.
    for i in 0..50 {
        names.push(format!("Document {}", i));
        let classification = classification_levels.choose(&mut rng).unwrap().to_string();
        document_classifications.push(classification.clone());

        let topic = tags.choose(&mut rng).unwrap().as_str();
        let doc_text = format!(
        "This is document {} discussing {}. It contains insights on {} developments and further observations.",
        i, topic, topic
    );
        tracing::debug!("Generated document {} with classification {} and topic {}", i, classification, topic);
        documents.push(doc_text);
    }

    tracing::info!("Creating GraphRAGManager");
    // Create the GraphRAGManager.
    let manager = match GraphRAGManager::new(
        classification_levels.clone(),
        team_name,
        tags.clone(),
        names,
        document_classifications,
        documents,
    )
    .await
    {
        Ok(mgr) => {
            tracing::info!("Successfully created GraphRAGManager");
            mgr
        },
        Err(e) => {
            tracing::error!("Failed to create GraphRAGManager: {:?}", e);
            return Err(e);
        }
    };

    // Issue a query for a particular classification (e.g. "public").
    let query = "What are the latest developments in technology?";
    tracing::info!("Issuing test query: {}", query);
    
    match manager.query_by_prompt("public", &tags, query).await {
        Ok(response) => {
            tracing::info!("Query successful");
            tracing::debug!("Query response: {}", response);
            println!("Query response: {}", response);
        },
        Err(e) => {
            tracing::error!("Query failed: {:?}", e);
            eprintln!("Query failed: {:?}", e);
        }
    }

    tracing::info!("Random classification test completed successfully");
    Ok(())
}
