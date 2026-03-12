pub mod proto {
    pub mod gritgrub {
        pub mod v1 {
            tonic::include_proto!("gritgrub.v1");
        }
    }
}

pub use proto::gritgrub::v1 as pb;

mod server;
pub use server::RepoServer;
