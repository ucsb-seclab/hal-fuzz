models = []

def register_model(mdl):
    models.append(mdl)


def configure_models(uc, config):
    for mdl in models:
        mdl.configure(uc, config)


class Model:

    @classmethod
    def configure(cls, uc, config):
        pass

    def __init__(self, *args, **kwargs):
        pass