import uuid

class ForFileOptions:
    def __init__(
            self,
            use_hash_lookup = True,
            use_cache = True,
            vaas_request_id = None
    ):
        self.vaas_request_id = vaas_request_id
        self.use_hash_lookup = use_hash_lookup
        self.use_cache = use_cache

    def from_vaas_config(self, vaas_options):
        self.use_hash_lookup = vaas_options.use_hash_lookup
        self.use_cache = vaas_options.use_cache
        return ForFileOptions()
