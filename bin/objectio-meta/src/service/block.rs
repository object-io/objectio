//! Block volumes, their chunks and snapshots (the gRPC side; the tables are in `block_meta`).

use super::*;

impl MetaService {
    pub(crate) async fn block_create_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_create_volume_impl(request.into_inner()).await?,
        ))
    }

    pub(crate) async fn block_get_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockGetVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_get_volume_impl(request.get_ref())?,
        ))
    }

    pub(crate) async fn block_list_volumes(
        &self,
        _request: Request<objectio_proto::metadata::BlockListVolumesRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListVolumesResponse>, Status> {
        Ok(Response::new(self.block_list_volumes_impl()))
    }

    pub(crate) async fn block_update_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockUpdateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_update_volume_impl(request.into_inner()).await?,
        ))
    }

    pub(crate) async fn block_delete_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_delete_volume_impl(request.into_inner()).await?,
        ))
    }

    pub(crate) async fn block_get_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockGetChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockGetChunksResponse>, Status> {
        Ok(Response::new(
            self.block_get_chunks_impl(request.get_ref())?,
        ))
    }

    pub(crate) async fn block_commit_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockCommitChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_commit_chunks_impl(request.into_inner()).await?,
        ))
    }

    pub(crate) async fn block_create_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Ok(Response::new(
            self.block_create_snapshot_impl(request.into_inner())
                .await?,
        ))
    }

    pub(crate) async fn block_get_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockGetSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Ok(Response::new(
            self.block_get_snapshot_impl(request.get_ref())?,
        ))
    }

    pub(crate) async fn block_list_snapshots(
        &self,
        request: Request<objectio_proto::metadata::BlockListSnapshotsRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListSnapshotsResponse>, Status> {
        Ok(Response::new(
            self.block_list_snapshots_impl(request.get_ref()),
        ))
    }

    pub(crate) async fn block_delete_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_delete_snapshot_impl(request.into_inner())
                .await?,
        ))
    }

    pub(crate) async fn block_clone_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCloneVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_clone_volume_impl(request.into_inner()).await?,
        ))
    }
}
