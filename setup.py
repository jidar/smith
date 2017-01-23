from setuptools import setup, find_packages

# Normal setup stuff
setup(
    name='smith',
    packages=find_packages(),
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'smith = smith.cli:cli']
    },
)
