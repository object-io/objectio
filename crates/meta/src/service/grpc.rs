//! The gRPC service: each call handled by its domain module.

use super::*;

#[tonic::async_trait]
impl MetadataService for MetaService {
    async fn get_metrics(
        &self,
        _request: Request<objectio_proto::metadata::GetMetricsRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetMetricsResponse>, Status> {
        Self::get_metrics(self, _request).await
    }

    async fn get_time(
        &self,
        _request: Request<objectio_proto::metadata::GetTimeRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetTimeResponse>, Status> {
        let unix_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Ok(Response::new(objectio_proto::metadata::GetTimeResponse {
            unix_millis,
        }))
    }

    async fn create_bucket(
        &self,
        request: Request<CreateBucketRequest>,
    ) -> Result<Response<CreateBucketResponse>, Status> {
        Self::create_bucket(self, request).await
    }

    async fn delete_bucket(
        &self,
        request: Request<DeleteBucketRequest>,
    ) -> Result<Response<DeleteBucketResponse>, Status> {
        Self::delete_bucket(self, request).await
    }

    async fn get_bucket(
        &self,
        request: Request<GetBucketRequest>,
    ) -> Result<Response<GetBucketResponse>, Status> {
        Self::get_bucket(self, request).await
    }

    async fn list_buckets(
        &self,
        request: Request<ListBucketsRequest>,
    ) -> Result<Response<ListBucketsResponse>, Status> {
        Self::list_buckets(self, request).await
    }

    async fn create_object(
        &self,
        request: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        Self::create_object(self, request).await
    }

    async fn delete_object(
        &self,
        request: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        Self::delete_object(self, request).await
    }

    async fn get_object(
        &self,
        _request: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        Self::get_object(self, _request).await
    }

    async fn list_objects(
        &self,
        request: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        Self::list_objects(self, request).await
    }

    async fn get_placement(
        &self,
        request: Request<GetPlacementRequest>,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        Self::get_placement(self, request).await
    }

    #[allow(clippy::result_large_err)]
    async fn create_multipart_upload(
        &self,
        request: Request<CreateMultipartUploadRequest>,
    ) -> Result<Response<CreateMultipartUploadResponse>, Status> {
        Self::create_multipart_upload(self, request).await
    }

    async fn get_multipart_upload(
        &self,
        request: Request<GetMultipartUploadRequest>,
    ) -> Result<Response<GetMultipartUploadResponse>, Status> {
        Self::get_multipart_upload(self, request).await
    }

    #[allow(clippy::result_large_err)]
    async fn register_part(
        &self,
        request: Request<RegisterPartRequest>,
    ) -> Result<Response<RegisterPartResponse>, Status> {
        Self::register_part(self, request).await
    }

    async fn list_parts(
        &self,
        request: Request<ListPartsRequest>,
    ) -> Result<Response<ListPartsResponse>, Status> {
        Self::list_parts(self, request).await
    }

    #[allow(clippy::result_large_err)]
    async fn complete_multipart_upload(
        &self,
        request: Request<CompleteMultipartUploadRequest>,
    ) -> Result<Response<CompleteMultipartUploadResponse>, Status> {
        Self::complete_multipart_upload(self, request).await
    }

    #[allow(clippy::result_large_err)]
    async fn abort_multipart_upload(
        &self,
        request: Request<AbortMultipartUploadRequest>,
    ) -> Result<Response<AbortMultipartUploadResponse>, Status> {
        Self::abort_multipart_upload(self, request).await
    }

    async fn list_multipart_uploads(
        &self,
        request: Request<ListMultipartUploadsRequest>,
    ) -> Result<Response<ListMultipartUploadsResponse>, Status> {
        Self::list_multipart_uploads(self, request).await
    }

    async fn set_bucket_policy(
        &self,
        request: Request<SetBucketPolicyRequest>,
    ) -> Result<Response<SetBucketPolicyResponse>, Status> {
        Self::set_bucket_policy(self, request).await
    }

    async fn get_bucket_policy(
        &self,
        request: Request<GetBucketPolicyRequest>,
    ) -> Result<Response<GetBucketPolicyResponse>, Status> {
        Self::get_bucket_policy(self, request).await
    }

    async fn delete_bucket_policy(
        &self,
        request: Request<DeleteBucketPolicyRequest>,
    ) -> Result<Response<DeleteBucketPolicyResponse>, Status> {
        Self::delete_bucket_policy(self, request).await
    }

    async fn register_osd(
        &self,
        request: Request<RegisterOsdRequest>,
    ) -> Result<Response<RegisterOsdResponse>, Status> {
        Self::register_osd(self, request).await
    }

    async fn get_listing_nodes(
        &self,
        request: Request<GetListingNodesRequest>,
    ) -> Result<Response<GetListingNodesResponse>, Status> {
        Self::get_listing_nodes(self, request).await
    }

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        Self::create_user(self, request).await
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        Self::get_user(self, request).await
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        Self::list_users(self, request).await
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        Self::delete_user(self, request).await
    }

    async fn create_access_key(
        &self,
        request: Request<CreateAccessKeyRequest>,
    ) -> Result<Response<CreateAccessKeyResponse>, Status> {
        Self::create_access_key(self, request).await
    }

    async fn list_access_keys(
        &self,
        request: Request<ListAccessKeysRequest>,
    ) -> Result<Response<ListAccessKeysResponse>, Status> {
        Self::list_access_keys(self, request).await
    }

    async fn delete_access_key(
        &self,
        request: Request<DeleteAccessKeyRequest>,
    ) -> Result<Response<DeleteAccessKeyResponse>, Status> {
        Self::delete_access_key(self, request).await
    }

    async fn get_access_key(
        &self,
        request: Request<objectio_proto::metadata::GetAccessKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetAccessKeyResponse>, Status> {
        Self::get_access_key(self, request).await
    }

    async fn get_access_key_for_auth(
        &self,
        request: Request<GetAccessKeyForAuthRequest>,
    ) -> Result<Response<GetAccessKeyForAuthResponse>, Status> {
        Self::get_access_key_for_auth(self, request).await
    }

    async fn iceberg_create_namespace(
        &self,
        request: Request<IcebergCreateNamespaceRequest>,
    ) -> Result<Response<IcebergCreateNamespaceResponse>, Status> {
        Self::iceberg_create_namespace(self, request).await
    }

    async fn iceberg_load_namespace(
        &self,
        request: Request<IcebergLoadNamespaceRequest>,
    ) -> Result<Response<IcebergLoadNamespaceResponse>, Status> {
        Self::iceberg_load_namespace(self, request).await
    }

    async fn iceberg_drop_namespace(
        &self,
        request: Request<IcebergDropNamespaceRequest>,
    ) -> Result<Response<IcebergDropNamespaceResponse>, Status> {
        Self::iceberg_drop_namespace(self, request).await
    }

    async fn iceberg_list_namespaces(
        &self,
        request: Request<IcebergListNamespacesRequest>,
    ) -> Result<Response<IcebergListNamespacesResponse>, Status> {
        Self::iceberg_list_namespaces(self, request).await
    }

    async fn iceberg_update_namespace_properties(
        &self,
        request: Request<IcebergUpdateNamespacePropertiesRequest>,
    ) -> Result<Response<IcebergUpdateNamespacePropertiesResponse>, Status> {
        Self::iceberg_update_namespace_properties(self, request).await
    }

    async fn iceberg_namespace_exists(
        &self,
        request: Request<IcebergNamespaceExistsRequest>,
    ) -> Result<Response<IcebergNamespaceExistsResponse>, Status> {
        Self::iceberg_namespace_exists(self, request).await
    }

    async fn iceberg_create_table(
        &self,
        request: Request<IcebergCreateTableRequest>,
    ) -> Result<Response<IcebergCreateTableResponse>, Status> {
        Self::iceberg_create_table(self, request).await
    }

    async fn iceberg_load_table(
        &self,
        request: Request<IcebergLoadTableRequest>,
    ) -> Result<Response<IcebergLoadTableResponse>, Status> {
        Self::iceberg_load_table(self, request).await
    }

    async fn iceberg_commit_table(
        &self,
        request: Request<IcebergCommitTableRequest>,
    ) -> Result<Response<IcebergCommitTableResponse>, Status> {
        Self::iceberg_commit_table(self, request).await
    }

    async fn iceberg_commit_transaction(
        &self,
        request: Request<IcebergCommitTransactionRequest>,
    ) -> Result<Response<IcebergCommitTransactionResponse>, Status> {
        Self::iceberg_commit_transaction(self, request).await
    }

    async fn iceberg_drop_table(
        &self,
        request: Request<IcebergDropTableRequest>,
    ) -> Result<Response<IcebergDropTableResponse>, Status> {
        Self::iceberg_drop_table(self, request).await
    }

    async fn iceberg_rename_table(
        &self,
        request: Request<IcebergRenameTableRequest>,
    ) -> Result<Response<IcebergRenameTableResponse>, Status> {
        Self::iceberg_rename_table(self, request).await
    }

    async fn iceberg_list_tables(
        &self,
        request: Request<IcebergListTablesRequest>,
    ) -> Result<Response<IcebergListTablesResponse>, Status> {
        Self::iceberg_list_tables(self, request).await
    }

    async fn iceberg_table_exists(
        &self,
        request: Request<IcebergTableExistsRequest>,
    ) -> Result<Response<IcebergTableExistsResponse>, Status> {
        Self::iceberg_table_exists(self, request).await
    }

    async fn iceberg_set_table_policy(
        &self,
        request: Request<IcebergSetTablePolicyRequest>,
    ) -> Result<Response<IcebergSetTablePolicyResponse>, Status> {
        Self::iceberg_set_table_policy(self, request).await
    }

    async fn iceberg_get_table_policy(
        &self,
        request: Request<IcebergGetTablePolicyRequest>,
    ) -> Result<Response<IcebergGetTablePolicyResponse>, Status> {
        Self::iceberg_get_table_policy(self, request).await
    }

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        Self::create_group(self, request).await
    }

    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        Self::delete_group(self, request).await
    }

    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        Self::list_groups(self, request).await
    }

    async fn add_user_to_group(
        &self,
        request: Request<AddUserToGroupRequest>,
    ) -> Result<Response<AddUserToGroupResponse>, Status> {
        Self::add_user_to_group(self, request).await
    }

    async fn remove_user_from_group(
        &self,
        request: Request<RemoveUserFromGroupRequest>,
    ) -> Result<Response<RemoveUserFromGroupResponse>, Status> {
        Self::remove_user_from_group(self, request).await
    }

    async fn get_user_groups(
        &self,
        request: Request<GetUserGroupsRequest>,
    ) -> Result<Response<GetUserGroupsResponse>, Status> {
        Self::get_user_groups(self, request).await
    }

    async fn create_data_filter(
        &self,
        request: Request<CreateDataFilterRequest>,
    ) -> Result<Response<CreateDataFilterResponse>, Status> {
        Self::create_data_filter(self, request).await
    }

    async fn list_data_filters(
        &self,
        request: Request<ListDataFiltersRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        Self::list_data_filters(self, request).await
    }

    async fn delete_data_filter(
        &self,
        request: Request<DeleteDataFilterRequest>,
    ) -> Result<Response<DeleteDataFilterResponse>, Status> {
        Self::delete_data_filter(self, request).await
    }

    async fn get_data_filters_for_principal(
        &self,
        request: Request<GetDataFiltersForPrincipalRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        Self::get_data_filters_for_principal(self, request).await
    }

    async fn delta_create_share(
        &self,
        request: Request<DeltaCreateShareRequest>,
    ) -> Result<Response<DeltaCreateShareResponse>, Status> {
        Self::delta_create_share(self, request).await
    }

    async fn delta_get_share(
        &self,
        request: Request<DeltaGetShareRequest>,
    ) -> Result<Response<DeltaGetShareResponse>, Status> {
        Self::delta_get_share(self, request).await
    }

    async fn delta_list_shares(
        &self,
        request: Request<DeltaListSharesRequest>,
    ) -> Result<Response<DeltaListSharesResponse>, Status> {
        Self::delta_list_shares(self, request).await
    }

    async fn delta_drop_share(
        &self,
        request: Request<DeltaDropShareRequest>,
    ) -> Result<Response<DeltaDropShareResponse>, Status> {
        Self::delta_drop_share(self, request).await
    }

    async fn delta_add_table(
        &self,
        request: Request<DeltaAddTableRequest>,
    ) -> Result<Response<DeltaAddTableResponse>, Status> {
        Self::delta_add_table(self, request).await
    }

    async fn delta_remove_table(
        &self,
        request: Request<DeltaRemoveTableRequest>,
    ) -> Result<Response<DeltaRemoveTableResponse>, Status> {
        Self::delta_remove_table(self, request).await
    }

    async fn delta_list_tables(
        &self,
        request: Request<DeltaListTablesRequest>,
    ) -> Result<Response<DeltaListTablesResponse>, Status> {
        Self::delta_list_tables(self, request).await
    }

    async fn delta_create_recipient(
        &self,
        request: Request<DeltaCreateRecipientRequest>,
    ) -> Result<Response<DeltaCreateRecipientResponse>, Status> {
        Self::delta_create_recipient(self, request).await
    }

    async fn delta_get_recipient_by_token(
        &self,
        request: Request<DeltaGetRecipientByTokenRequest>,
    ) -> Result<Response<DeltaGetRecipientByTokenResponse>, Status> {
        Self::delta_get_recipient_by_token(self, request).await
    }

    async fn delta_list_recipients(
        &self,
        _request: Request<DeltaListRecipientsRequest>,
    ) -> Result<Response<DeltaListRecipientsResponse>, Status> {
        Self::delta_list_recipients(self, _request).await
    }

    async fn delta_drop_recipient(
        &self,
        request: Request<DeltaDropRecipientRequest>,
    ) -> Result<Response<DeltaDropRecipientResponse>, Status> {
        Self::delta_drop_recipient(self, request).await
    }

    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        Self::get_config(self, request).await
    }

    async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        Self::set_config(self, request).await
    }

    async fn delete_config(
        &self,
        request: Request<DeleteConfigRequest>,
    ) -> Result<Response<DeleteConfigResponse>, Status> {
        Self::delete_config(self, request).await
    }

    async fn set_osd_admin_state(
        &self,
        request: Request<SetOsdAdminStateRequest>,
    ) -> Result<Response<SetOsdAdminStateResponse>, Status> {
        Self::set_osd_admin_state(self, request).await
    }

    async fn get_drain_status(
        &self,
        _request: Request<GetDrainStatusRequest>,
    ) -> Result<Response<GetDrainStatusResponse>, Status> {
        Self::get_drain_status(self, _request).await
    }

    async fn get_rebalance_status(
        &self,
        _request: Request<GetRebalanceStatusRequest>,
    ) -> Result<Response<GetRebalanceStatusResponse>, Status> {
        Self::get_rebalance_status(self, _request).await
    }

    async fn list_config(
        &self,
        request: Request<ListConfigRequest>,
    ) -> Result<Response<ListConfigResponse>, Status> {
        Self::list_config(self, request).await
    }

    async fn create_pool(
        &self,
        request: Request<CreatePoolRequest>,
    ) -> Result<Response<CreatePoolResponse>, Status> {
        Self::create_pool(self, request).await
    }

    async fn get_pool(
        &self,
        request: Request<GetPoolRequest>,
    ) -> Result<Response<GetPoolResponse>, Status> {
        Self::get_pool(self, request).await
    }

    async fn list_pools(
        &self,
        _request: Request<ListPoolsRequest>,
    ) -> Result<Response<ListPoolsResponse>, Status> {
        Self::list_pools(self, _request).await
    }

    async fn update_pool(
        &self,
        request: Request<UpdatePoolRequest>,
    ) -> Result<Response<UpdatePoolResponse>, Status> {
        Self::update_pool(self, request).await
    }

    async fn delete_pool(
        &self,
        request: Request<DeletePoolRequest>,
    ) -> Result<Response<DeletePoolResponse>, Status> {
        Self::delete_pool(self, request).await
    }

    async fn get_placement_group(
        &self,
        request: Request<GetPlacementGroupRequest>,
    ) -> Result<Response<GetPlacementGroupResponse>, Status> {
        Self::get_placement_group(self, request).await
    }

    async fn list_placement_groups(
        &self,
        request: Request<ListPlacementGroupsRequest>,
    ) -> Result<Response<ListPlacementGroupsResponse>, Status> {
        Self::list_placement_groups(self, request).await
    }

    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        Self::create_tenant(self, request).await
    }

    async fn get_tenant(
        &self,
        request: Request<GetTenantRequest>,
    ) -> Result<Response<GetTenantResponse>, Status> {
        Self::get_tenant(self, request).await
    }

    async fn list_tenants(
        &self,
        _request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        Self::list_tenants(self, _request).await
    }

    async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<UpdateTenantResponse>, Status> {
        Self::update_tenant(self, request).await
    }

    async fn delete_tenant(
        &self,
        request: Request<DeleteTenantRequest>,
    ) -> Result<Response<DeleteTenantResponse>, Status> {
        Self::delete_tenant(self, request).await
    }

    async fn iceberg_create_warehouse(
        &self,
        request: Request<IcebergCreateWarehouseRequest>,
    ) -> Result<Response<IcebergCreateWarehouseResponse>, Status> {
        Self::iceberg_create_warehouse(self, request).await
    }

    async fn iceberg_list_warehouses(
        &self,
        request: Request<IcebergListWarehousesRequest>,
    ) -> Result<Response<IcebergListWarehousesResponse>, Status> {
        Self::iceberg_list_warehouses(self, request).await
    }

    async fn iceberg_delete_warehouse(
        &self,
        request: Request<IcebergDeleteWarehouseRequest>,
    ) -> Result<Response<IcebergDeleteWarehouseResponse>, Status> {
        Self::iceberg_delete_warehouse(self, request).await
    }

    async fn unity_create_catalog(
        &self,
        request: Request<UnityCreateCatalogRequest>,
    ) -> Result<Response<UnityCreateCatalogResponse>, Status> {
        Self::unity_create_catalog(self, request).await
    }

    async fn unity_list_catalogs(
        &self,
        request: Request<UnityListCatalogsRequest>,
    ) -> Result<Response<UnityListCatalogsResponse>, Status> {
        Self::unity_list_catalogs(self, request).await
    }

    async fn unity_get_catalog(
        &self,
        request: Request<UnityGetCatalogRequest>,
    ) -> Result<Response<UnityGetCatalogResponse>, Status> {
        Self::unity_get_catalog(self, request).await
    }

    async fn unity_update_catalog(
        &self,
        request: Request<UnityUpdateCatalogRequest>,
    ) -> Result<Response<UnityUpdateCatalogResponse>, Status> {
        Self::unity_update_catalog(self, request).await
    }

    async fn unity_delete_catalog(
        &self,
        request: Request<UnityDeleteCatalogRequest>,
    ) -> Result<Response<UnityDeleteCatalogResponse>, Status> {
        Self::unity_delete_catalog(self, request).await
    }

    async fn unity_create_schema(
        &self,
        request: Request<UnityCreateSchemaRequest>,
    ) -> Result<Response<UnityCreateSchemaResponse>, Status> {
        Self::unity_create_schema(self, request).await
    }

    async fn unity_list_schemas(
        &self,
        request: Request<UnityListSchemasRequest>,
    ) -> Result<Response<UnityListSchemasResponse>, Status> {
        Self::unity_list_schemas(self, request).await
    }

    async fn unity_get_schema(
        &self,
        request: Request<UnityGetSchemaRequest>,
    ) -> Result<Response<UnityGetSchemaResponse>, Status> {
        Self::unity_get_schema(self, request).await
    }

    async fn unity_update_schema(
        &self,
        request: Request<UnityUpdateSchemaRequest>,
    ) -> Result<Response<UnityUpdateSchemaResponse>, Status> {
        Self::unity_update_schema(self, request).await
    }

    async fn unity_delete_schema(
        &self,
        request: Request<UnityDeleteSchemaRequest>,
    ) -> Result<Response<UnityDeleteSchemaResponse>, Status> {
        Self::unity_delete_schema(self, request).await
    }

    async fn unity_create_table(
        &self,
        request: Request<UnityCreateTableRequest>,
    ) -> Result<Response<UnityCreateTableResponse>, Status> {
        Self::unity_create_table(self, request).await
    }

    async fn unity_list_tables(
        &self,
        request: Request<UnityListTablesRequest>,
    ) -> Result<Response<UnityListTablesResponse>, Status> {
        Self::unity_list_tables(self, request).await
    }

    async fn unity_get_table(
        &self,
        request: Request<UnityGetTableRequest>,
    ) -> Result<Response<UnityGetTableResponse>, Status> {
        Self::unity_get_table(self, request).await
    }

    async fn unity_delete_table(
        &self,
        request: Request<UnityDeleteTableRequest>,
    ) -> Result<Response<UnityDeleteTableResponse>, Status> {
        Self::unity_delete_table(self, request).await
    }

    async fn unity_create_function(
        &self,
        request: Request<UnityCreateFunctionRequest>,
    ) -> Result<Response<UnityCreateFunctionResponse>, Status> {
        Self::unity_create_function(self, request).await
    }

    async fn unity_list_functions(
        &self,
        request: Request<UnityListFunctionsRequest>,
    ) -> Result<Response<UnityListFunctionsResponse>, Status> {
        Self::unity_list_functions(self, request).await
    }

    async fn unity_get_function(
        &self,
        request: Request<UnityGetFunctionRequest>,
    ) -> Result<Response<UnityGetFunctionResponse>, Status> {
        Self::unity_get_function(self, request).await
    }

    async fn unity_delete_function(
        &self,
        request: Request<UnityDeleteFunctionRequest>,
    ) -> Result<Response<UnityDeleteFunctionResponse>, Status> {
        Self::unity_delete_function(self, request).await
    }

    async fn unity_create_volume(
        &self,
        request: Request<UnityCreateVolumeRequest>,
    ) -> Result<Response<UnityCreateVolumeResponse>, Status> {
        Self::unity_create_volume(self, request).await
    }

    async fn unity_list_volumes(
        &self,
        request: Request<UnityListVolumesRequest>,
    ) -> Result<Response<UnityListVolumesResponse>, Status> {
        Self::unity_list_volumes(self, request).await
    }

    async fn unity_get_volume(
        &self,
        request: Request<UnityGetVolumeRequest>,
    ) -> Result<Response<UnityGetVolumeResponse>, Status> {
        Self::unity_get_volume(self, request).await
    }

    async fn unity_delete_volume(
        &self,
        request: Request<UnityDeleteVolumeRequest>,
    ) -> Result<Response<UnityDeleteVolumeResponse>, Status> {
        Self::unity_delete_volume(self, request).await
    }

    async fn unity_create_model(
        &self,
        request: Request<UnityCreateModelRequest>,
    ) -> Result<Response<UnityCreateModelResponse>, Status> {
        Self::unity_create_model(self, request).await
    }

    async fn unity_list_models(
        &self,
        request: Request<UnityListModelsRequest>,
    ) -> Result<Response<UnityListModelsResponse>, Status> {
        Self::unity_list_models(self, request).await
    }

    async fn unity_get_model(
        &self,
        request: Request<UnityGetModelRequest>,
    ) -> Result<Response<UnityGetModelResponse>, Status> {
        Self::unity_get_model(self, request).await
    }

    async fn unity_delete_model(
        &self,
        request: Request<UnityDeleteModelRequest>,
    ) -> Result<Response<UnityDeleteModelResponse>, Status> {
        Self::unity_delete_model(self, request).await
    }

    async fn unity_create_model_version(
        &self,
        request: Request<UnityCreateModelVersionRequest>,
    ) -> Result<Response<UnityCreateModelVersionResponse>, Status> {
        Self::unity_create_model_version(self, request).await
    }

    async fn unity_list_model_versions(
        &self,
        request: Request<UnityListModelVersionsRequest>,
    ) -> Result<Response<UnityListModelVersionsResponse>, Status> {
        Self::unity_list_model_versions(self, request).await
    }

    async fn unity_get_model_version(
        &self,
        request: Request<UnityGetModelVersionRequest>,
    ) -> Result<Response<UnityGetModelVersionResponse>, Status> {
        Self::unity_get_model_version(self, request).await
    }

    async fn unity_update_model_version_status(
        &self,
        request: Request<UnityUpdateModelVersionStatusRequest>,
    ) -> Result<Response<UnityUpdateModelVersionStatusResponse>, Status> {
        Self::unity_update_model_version_status(self, request).await
    }

    async fn unity_delete_model_version(
        &self,
        request: Request<UnityDeleteModelVersionRequest>,
    ) -> Result<Response<UnityDeleteModelVersionResponse>, Status> {
        Self::unity_delete_model_version(self, request).await
    }

    async fn unity_set_catalog_policy(
        &self,
        request: Request<UnitySetCatalogPolicyRequest>,
    ) -> Result<Response<UnitySetCatalogPolicyResponse>, Status> {
        Self::unity_set_catalog_policy(self, request).await
    }

    async fn unity_get_catalog_policy(
        &self,
        request: Request<UnityGetCatalogPolicyRequest>,
    ) -> Result<Response<UnityGetCatalogPolicyResponse>, Status> {
        Self::unity_get_catalog_policy(self, request).await
    }

    async fn unity_set_schema_policy(
        &self,
        request: Request<UnitySetSchemaPolicyRequest>,
    ) -> Result<Response<UnitySetSchemaPolicyResponse>, Status> {
        Self::unity_set_schema_policy(self, request).await
    }

    async fn unity_get_schema_policy(
        &self,
        request: Request<UnityGetSchemaPolicyRequest>,
    ) -> Result<Response<UnityGetSchemaPolicyResponse>, Status> {
        Self::unity_get_schema_policy(self, request).await
    }

    async fn unity_set_table_policy(
        &self,
        request: Request<UnitySetTablePolicyRequest>,
    ) -> Result<Response<UnitySetTablePolicyResponse>, Status> {
        Self::unity_set_table_policy(self, request).await
    }

    async fn unity_set_table_security(
        &self,
        request: Request<UnitySetTableSecurityRequest>,
    ) -> Result<Response<UnitySetTableSecurityResponse>, Status> {
        Self::unity_set_table_security(self, request).await
    }

    async fn unity_get_table_policy(
        &self,
        request: Request<UnityGetTablePolicyRequest>,
    ) -> Result<Response<UnityGetTablePolicyResponse>, Status> {
        Self::unity_get_table_policy(self, request).await
    }

    async fn put_bucket_versioning(
        &self,
        request: Request<PutBucketVersioningRequest>,
    ) -> Result<Response<PutBucketVersioningResponse>, Status> {
        Self::put_bucket_versioning(self, request).await
    }

    async fn share_stripes(
        &self,
        request: Request<objectio_proto::metadata::ShareStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ShareStripesResponse>, Status> {
        Self::share_stripes(self, request).await
    }

    async fn release_stripes(
        &self,
        request: Request<objectio_proto::metadata::ReleaseStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReleaseStripesResponse>, Status> {
        Self::release_stripes(self, request).await
    }

    async fn intend_pack(
        &self,
        request: Request<objectio_proto::metadata::IntendPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::IntendPackResponse>, Status> {
        Self::intend_pack(self, request).await
    }

    async fn seal_pack(
        &self,
        request: Request<objectio_proto::metadata::SealPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::SealPackResponse>, Status> {
        Self::seal_pack(self, request).await
    }

    async fn abort_pack(
        &self,
        request: Request<objectio_proto::metadata::AbortPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::AbortPackResponse>, Status> {
        Self::abort_pack(self, request).await
    }

    async fn get_pack(
        &self,
        request: Request<objectio_proto::metadata::GetPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetPackResponse>, Status> {
        Self::get_pack(self, request).await
    }

    async fn list_packs(
        &self,
        request: Request<objectio_proto::metadata::ListPacksRequest>,
    ) -> Result<Response<objectio_proto::metadata::ListPacksResponse>, Status> {
        Self::list_packs(self, request).await
    }

    async fn pack_move_shard(
        &self,
        request: Request<objectio_proto::metadata::PackMoveShardRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackMoveShardResponse>, Status> {
        Self::pack_move_shard(self, request).await
    }

    async fn pack_settle(
        &self,
        request: Request<objectio_proto::metadata::PackSettleRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackSettleResponse>, Status> {
        Self::pack_settle(self, request).await
    }

    async fn block_create_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Self::block_create_volume(self, request).await
    }

    async fn block_get_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockGetVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Self::block_get_volume(self, request).await
    }

    async fn block_list_volumes(
        &self,
        _request: Request<objectio_proto::metadata::BlockListVolumesRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListVolumesResponse>, Status> {
        Self::block_list_volumes(self, _request).await
    }

    async fn block_update_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockUpdateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Self::block_update_volume(self, request).await
    }

    async fn block_delete_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Self::block_delete_volume(self, request).await
    }

    async fn block_get_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockGetChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockGetChunksResponse>, Status> {
        Self::block_get_chunks(self, request).await
    }

    async fn block_commit_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockCommitChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Self::block_commit_chunks(self, request).await
    }

    async fn block_create_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Self::block_create_snapshot(self, request).await
    }

    async fn block_get_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockGetSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Self::block_get_snapshot(self, request).await
    }

    async fn block_list_snapshots(
        &self,
        request: Request<objectio_proto::metadata::BlockListSnapshotsRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListSnapshotsResponse>, Status> {
        Self::block_list_snapshots(self, request).await
    }

    async fn block_delete_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Self::block_delete_snapshot(self, request).await
    }

    async fn block_clone_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCloneVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Self::block_clone_volume(self, request).await
    }

    async fn set_bucket_dedup(
        &self,
        request: Request<objectio_proto::metadata::SetBucketDedupRequest>,
    ) -> Result<Response<objectio_proto::metadata::SetBucketDedupResponse>, Status> {
        Self::set_bucket_dedup(self, request).await
    }

    async fn get_dedup_policy(
        &self,
        request: Request<objectio_proto::metadata::GetDedupPolicyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetDedupPolicyResponse>, Status> {
        Self::get_dedup_policy(self, request).await
    }

    async fn locate_chunks(
        &self,
        request: Request<objectio_proto::metadata::LocateChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::LocateChunksResponse>, Status> {
        Self::locate_chunks(self, request).await
    }

    async fn set_bucket_quota(
        &self,
        request: Request<SetBucketQuotaRequest>,
    ) -> Result<Response<SetBucketQuotaResponse>, Status> {
        Self::set_bucket_quota(self, request).await
    }

    async fn set_bucket_owner(
        &self,
        request: Request<SetBucketOwnerRequest>,
    ) -> Result<Response<SetBucketOwnerResponse>, Status> {
        Self::set_bucket_owner(self, request).await
    }

    async fn get_bucket_versioning(
        &self,
        request: Request<GetBucketVersioningRequest>,
    ) -> Result<Response<GetBucketVersioningResponse>, Status> {
        Self::get_bucket_versioning(self, request).await
    }

    async fn put_object_lock_configuration(
        &self,
        request: Request<PutObjectLockConfigRequest>,
    ) -> Result<Response<PutObjectLockConfigResponse>, Status> {
        Self::put_object_lock_configuration(self, request).await
    }

    async fn get_object_lock_configuration(
        &self,
        request: Request<GetObjectLockConfigRequest>,
    ) -> Result<Response<GetObjectLockConfigResponse>, Status> {
        Self::get_object_lock_configuration(self, request).await
    }

    async fn put_bucket_lifecycle(
        &self,
        request: Request<PutBucketLifecycleRequest>,
    ) -> Result<Response<PutBucketLifecycleResponse>, Status> {
        Self::put_bucket_lifecycle(self, request).await
    }

    async fn get_bucket_lifecycle(
        &self,
        request: Request<GetBucketLifecycleRequest>,
    ) -> Result<Response<GetBucketLifecycleResponse>, Status> {
        Self::get_bucket_lifecycle(self, request).await
    }

    async fn delete_bucket_lifecycle(
        &self,
        request: Request<DeleteBucketLifecycleRequest>,
    ) -> Result<Response<DeleteBucketLifecycleResponse>, Status> {
        Self::delete_bucket_lifecycle(self, request).await
    }

    async fn put_bucket_encryption(
        &self,
        request: Request<PutBucketEncryptionRequest>,
    ) -> Result<Response<PutBucketEncryptionResponse>, Status> {
        Self::put_bucket_encryption(self, request).await
    }

    async fn get_bucket_encryption(
        &self,
        request: Request<GetBucketEncryptionRequest>,
    ) -> Result<Response<GetBucketEncryptionResponse>, Status> {
        Self::get_bucket_encryption(self, request).await
    }

    async fn report_version(
        &self,
        request: Request<objectio_proto::metadata::ReportVersionRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReportVersionResponse>, Status> {
        Self::report_version(self, request).await
    }

    async fn get_upgrade_status(
        &self,
        _request: Request<objectio_proto::metadata::GetUpgradeStatusRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetUpgradeStatusResponse>, Status> {
        Self::get_upgrade_status(self, _request).await
    }

    async fn finalize_upgrade(
        &self,
        request: Request<objectio_proto::metadata::FinalizeUpgradeRequest>,
    ) -> Result<Response<objectio_proto::metadata::FinalizeUpgradeResponse>, Status> {
        Self::finalize_upgrade(self, request).await
    }

    async fn acquire_lease(
        &self,
        request: Request<objectio_proto::metadata::AcquireLeaseRequest>,
    ) -> Result<Response<objectio_proto::metadata::AcquireLeaseResponse>, Status> {
        Self::acquire_lease(self, request).await
    }

    async fn get_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::GetBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetBucketSettingResponse>, Status> {
        Self::get_bucket_setting(self, request).await
    }

    async fn put_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::PutBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::PutBucketSettingResponse>, Status> {
        Self::put_bucket_setting(self, request).await
    }

    async fn delete_bucket_encryption(
        &self,
        request: Request<DeleteBucketEncryptionRequest>,
    ) -> Result<Response<DeleteBucketEncryptionResponse>, Status> {
        Self::delete_bucket_encryption(self, request).await
    }

    async fn create_kms_key(
        &self,
        request: Request<CreateKmsKeyRequest>,
    ) -> Result<Response<CreateKmsKeyResponse>, Status> {
        Self::create_kms_key(self, request).await
    }

    async fn get_kms_key(
        &self,
        request: Request<GetKmsKeyRequest>,
    ) -> Result<Response<GetKmsKeyResponse>, Status> {
        Self::get_kms_key(self, request).await
    }

    async fn list_kms_keys(
        &self,
        request: Request<ListKmsKeysRequest>,
    ) -> Result<Response<ListKmsKeysResponse>, Status> {
        Self::list_kms_keys(self, request).await
    }

    async fn delete_kms_key(
        &self,
        request: Request<DeleteKmsKeyRequest>,
    ) -> Result<Response<DeleteKmsKeyResponse>, Status> {
        Self::delete_kms_key(self, request).await
    }

    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        Self::create_policy(self, request).await
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        Self::get_policy(self, request).await
    }

    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        Self::list_policies(self, _request).await
    }

    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        Self::delete_policy(self, request).await
    }

    async fn attach_policy(
        &self,
        request: Request<AttachPolicyRequest>,
    ) -> Result<Response<AttachPolicyResponse>, Status> {
        Self::attach_policy(self, request).await
    }

    async fn detach_policy(
        &self,
        request: Request<DetachPolicyRequest>,
    ) -> Result<Response<DetachPolicyResponse>, Status> {
        Self::detach_policy(self, request).await
    }

    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        Self::update_policy(self, request).await
    }

    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UpdateUserResponse>, Status> {
        Self::update_user(self, request).await
    }

    async fn update_access_key(
        &self,
        request: Request<UpdateAccessKeyRequest>,
    ) -> Result<Response<UpdateAccessKeyResponse>, Status> {
        Self::update_access_key(self, request).await
    }

    async fn get_sts_signing_key(
        &self,
        _request: Request<objectio_proto::metadata::GetStsSigningKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetStsSigningKeyResponse>, Status> {
        Self::get_sts_signing_key(self, _request).await
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        Self::create_role(self, request).await
    }

    async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        Self::get_role(self, request).await
    }

    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        Self::list_roles(self, request).await
    }

    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        Self::update_role(self, request).await
    }

    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        Self::delete_role(self, request).await
    }

    async fn update_group(
        &self,
        request: Request<UpdateGroupRequest>,
    ) -> Result<Response<UpdateGroupResponse>, Status> {
        Self::update_group(self, request).await
    }

    async fn put_inline_policy(
        &self,
        request: Request<PutInlinePolicyRequest>,
    ) -> Result<Response<PutInlinePolicyResponse>, Status> {
        Self::put_inline_policy(self, request).await
    }

    async fn get_inline_policy(
        &self,
        request: Request<GetInlinePolicyRequest>,
    ) -> Result<Response<GetInlinePolicyResponse>, Status> {
        Self::get_inline_policy(self, request).await
    }

    async fn list_inline_policies(
        &self,
        request: Request<ListInlinePoliciesRequest>,
    ) -> Result<Response<ListInlinePoliciesResponse>, Status> {
        Self::list_inline_policies(self, request).await
    }

    async fn delete_inline_policy(
        &self,
        request: Request<DeleteInlinePolicyRequest>,
    ) -> Result<Response<DeleteInlinePolicyResponse>, Status> {
        Self::delete_inline_policy(self, request).await
    }

    async fn heal_enqueue(
        &self,
        request: Request<objectio_proto::metadata::HealEnqueueRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealEnqueueResponse>, Status> {
        Self::heal_enqueue(self, request).await
    }

    async fn heal_list(
        &self,
        request: Request<objectio_proto::metadata::HealListRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealListResponse>, Status> {
        Self::heal_list(self, request).await
    }

    async fn heal_claim(
        &self,
        request: Request<objectio_proto::metadata::HealClaimRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealClaimResponse>, Status> {
        Self::heal_claim(self, request).await
    }

    async fn heal_done(
        &self,
        request: Request<objectio_proto::metadata::HealDoneRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealDoneResponse>, Status> {
        Self::heal_done(self, request).await
    }

    async fn list_attached_policies(
        &self,
        request: Request<ListAttachedPoliciesRequest>,
    ) -> Result<Response<ListAttachedPoliciesResponse>, Status> {
        Self::list_attached_policies(self, request).await
    }
}
