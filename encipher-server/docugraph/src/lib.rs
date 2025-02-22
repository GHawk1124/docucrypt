use rust_bert::pipelines::sentence_embeddings::{SentenceEmbeddingsBuilder, SentenceEmbeddingsModel};
use std::error::Error;

pub struct DocumentEmbedder {
    model: SentenceEmbeddingsModel,
}

impl DocumentEmbedder {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let model = SentenceEmbeddingsBuilder::local("deepseek-r1")
            .create_model()?;
        
        Ok(Self { model })
    }

    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>, Box<dyn Error>> {
        let embeddings = self.model.encode(&[text])?;
        Ok(embeddings[0].clone())
    }

    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        dot_product / (norm_a * norm_b)
    }

    pub fn find_similar_documents(&self, query: &str, documents: &[String]) -> Result<Vec<(usize, f32)>, Box<dyn Error>> {
        let query_embedding = self.embed_text(query)?;
        
        let mut similarities: Vec<(usize, f32)> = documents
            .iter()
            .enumerate()
            .map(|(i, doc)| {
                let doc_embedding = self.embed_text(doc)?;
                Ok((i, Self::cosine_similarity(&query_embedding, &doc_embedding)))
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        Ok(similarities)
    }
}
