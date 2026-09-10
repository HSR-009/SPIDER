from setuptools import setup
from setuptools.command.install import install
import os

class CustomInstall(install):
    def run(self):
        os.system("whoami")
        install.run(self)

setup(
    name="toy-malicious-package",
    version="1.0.0",
    cmdclass={"install": CustomInstall},
)