"""Synthetic fixture: harmless custom install command."""
import os
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        os.system("echo SPIDER-FIXTURE install hook ran")


setup(
    name="demo-installhook",
    version="0.1.0",
    packages=["demo_installhook"],
    cmdclass={"install": PostInstall},
)
