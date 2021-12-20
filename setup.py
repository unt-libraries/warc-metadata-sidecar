from setuptools import setup


with open('README.md', 'r') as readme_f:
    long_description = readme_f.read()

with open('requirements.txt', 'r') as f:
    dependencies = f.read().split()


setup(
    name='warc-metadata-sidecar',
    version='1.0',
    url='https://github/unt-libraries/warc-metadata-sidecar/',
    author='University of North Texas Libraries',
    author_email='gracie.flores@unt.edu',
    license='',
    py_modules=['warc-metadata-sidecar'],
    scripts=['warc-metadata-sidecar.py'],
    description='A script that creates a sidecar from a warc file',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=dependencies,
)
