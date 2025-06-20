import uuid

class ForStreamOptions:
    def __init__(
            self,
            use_hash_lookup = True,
            vaas_request_id = None
    ):
        self.vaas_request_id = vaas_request_id
        self.use_hash_lookup = use_hash_lookup

    def from_vaas_config(self, vaas_options):
        self.use_hash_lookup = vaas_options.use_hash_lookup
        return ForStreamOptions()
