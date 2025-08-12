from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
    
try:
    from Cython.Build import cythonize
    USE_CYTHON = True
except ImportError:
    USE_CYTHON = False
    
ext = ".pyx" if USE_CYTHON else ".c"

extensions = [
    Extension(
        "wannacri.usm.tools_cython",
        [os.path.join("wannacri", "usm", "tools_cython" + ext)]
    )
]

if USE_CYTHON:
    extensions = cythonize(extensions, compiler_directives={"language_level": "3"})

setup(
    name="WannaCRI",
    description="Criware media formats library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="donmai",
    url="https://github.com/donmai-me/WannaCRI",
    ext_modules=extensions,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Games/Entertainment",
    ],
    packages=[
        "wannacri",
        "wannacri.usm",
        "wannacri.usm.media",
    ],
    entry_points={
        "console_scripts": ["wannacri=wannacri:main"],
    },
    python_requires="~=3.8",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=["ffmpeg-python~=0.2.0"],
)
