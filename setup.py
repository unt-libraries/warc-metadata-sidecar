from setuptools import setup


with open('README.md', 'r') as readme_f:
    long_description = readme_f.read()

with open('requirements.txt', 'r') as f:
    dependencies = f.read().split()


setup(
    name='warc-metadata-sidecar',
    version='1.0',
    url='https://github.com/unt-libraries/warc-metadata-sidecar/',
    author='University of North Texas Libraries',
    author_email='gracie.flores@unt.edu',
    license='',
    py_modules=['warc_metadata_sidecar'],
    scripts=['warc_metadata_sidecar.py', 'sidecar2cdxj.py'],
    description='A script that creates a metadata sidecar file from a WARC file',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=dependencies,
    classifiers=[
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ]
)
