from setuptools import setup, find_packages

setup(
    name='auth-service',
    version='1.0',
    description='Authentification service for SKA',
    author='Amani Ben Hassine',
    author_email='amani.benhassine@esprit.tn',
    packages=find_packages(),
    install_requires=[
        'django',
        'djangorestframework',
        'PyJWT',
        'py-eureka-client',
        'requests',
        'google-auth',
        'psycopg2',
        'django-cors-headers',
    ],
)
