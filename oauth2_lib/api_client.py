class ApiClientProxy:
    """
    Proxy over a swagger API client instance that allows passing request headers.

    Where the API client is reused, this proxy is intended to be used on a
    per-request basis.
    """

    def __init__(self, target, request_headers):
        self.target = target
        self.request_headers = request_headers

    def call_api(
        self,
        resource_path,
        method,
        path_params=None,
        query_params=None,
        header_params=None,
        body=None,
        post_params=None,
        files=None,
        response_type=None,
        auth_settings=None,
        async_req=None,
        _return_http_data_only=None,
        collection_formats=None,
        _preload_content=True,
        _request_timeout=None,
    ):
        all_headers = {**self.request_headers, **header_params}
        return self.target.call_api(
            resource_path,
            method,
            path_params,
            query_params,
            all_headers,
            body,
            post_params,
            files,
            response_type,
            auth_settings,
            async_req,
            _return_http_data_only,
            collection_formats,
            _preload_content,
            _request_timeout,
        )

    def __getattr__(self, name):
        return getattr(self.target, name)

    def __repr__(self):
        return "[ApiClientProxy] %s".format(repr(self.target))
