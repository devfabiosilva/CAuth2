from distutils.core import setup, Extension

def main():

    setup(name="panelauth",
        version="0.2.0",
        description="PLC panel / IoT AUTH2 and HMAC protocol modules for Python 3 using C library setup",
        author="Fábio Pereira da Silva",
        author_email="fabioegel@gmail.com",
        url="https://github.com/devfabiosilva/CAuth2",
        maintainer_email="fabioegel@gmail.com",
        ext_modules=[Extension("panelauth", ["module.c"],
            library_dirs=['build/lib/shared'],
            libraries=['cauth2_shared'],
            include_dirs=['build/include']
        )])

if __name__ == "__main__":
    main()
