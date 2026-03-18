import docker
from docker.errors import DockerException

class Collector:
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            raise RuntimeError("Docker daemon is not available") from e

    def list_containers(self):
        return [c.name for c in self.client.containers.list()]

    def inspect_container(self, name):
        container = self.client.containers.get(name)
        return container.attrs
