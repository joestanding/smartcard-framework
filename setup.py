from distutils.core import setup

setup(
    name='scframework',
    version='0.01',
    packages=['scframework',],
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    long_description='Smartcard things',
    scripts=[
        'tools/scdecode',
        'tools/scenumapps',
        'tools/sccli'
    ],
    install_requires=[
        'colorama==0.3.7',
        'tabulate==0.8.2',
        'pyscard==1.9.8'
    ]
)
