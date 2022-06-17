CC=gcc
STRIP=strip
CURDIR=$(PWD)
INCLUDEDIR=$(CURDIR)/include
MBEDTLS_GIT=https://github.com/Mbed-TLS/mbedtls.git
MBEDTLS_BRANCH=v3.1.0
MBED_INCLUDE_DIR=$(CURDIR)/downloads/mbedtls/build/compiled/include
MBED_LIB_DIR=$(CURDIR)/downloads/mbedtls/build/compiled/lib
MBED_LIB_OBJ_DIR=$(CURDIR)/downloads/mbedtls/build/library/CMakeFiles/mbedcrypto.dir
MBED_CRYPTO_NAME=libmbedcrypto.a
AR=ar rcs
LIBANAME=cauth2
CAUTH_BUILD_DIR_NAME=build
CAUTH_BUILD_DIR=$(CURDIR)/$(CAUTH_BUILD_DIR_NAME)
CAUTH_BUILD_INCLUDE_DIR_NAME=include
CAUTH_BUILD_INCLUDE_DIR=$(CAUTH_BUILD_DIR)/$(CAUTH_BUILD_INCLUDE_DIR_NAME)

all: main

cyodecode_shared.o: src/CyoDecode.c src/CyoEncode.c
	@echo "Build Base32 Utilities shared object"
	@$(CC) -O2 -c src/CyoDecode.c -Iinclude -fPIC -o cyodecode_shared.o -Wall

cyodecode.o: src/CyoDecode.c src/CyoEncode.c
	@echo "Build Base32 Utilities object"
	@$(CC) -O2 -c src/CyoDecode.c -Iinclude -o cyodecode.o -Wall

mbedtls:
ifeq ("$(wildcard $(CURDIR)/downloads)","")
	@echo "Creating temporary folder for download dependencies ..."
	@mkdir $(CURDIR)/downloads -v
endif

	@echo "Check if mbdedTLS exists ..."
ifneq ("$(wildcard $(CURDIR)/downloads/mbedtls)","")
	@echo "Already cloned. Skip"
else
	@echo "Cloning branch $(MBEDTLS_BRANCH) from $(MBEDTLS_GIT)"
	pwd; cd $(CURDIR)/downloads; pwd; git clone -b $(MBEDTLS_BRANCH) $(MBEDTLS_GIT); cd ..; pwd
endif

ifneq ("$(wildcard $(CURDIR)/downloads/mbedtls/build/compiled)","")
	@echo "Already compiled. Skip"
else
	@echo "Preparing to compile mbedTLS $(MBEDTLS_BRANCH) ..."
	pwd; cd $(CURDIR)/downloads/mbedtls; pwd; \
	mkdir $(CURDIR)/downloads/mbedtls/build -v; \
	cd $(CURDIR)/downloads/mbedtls/build; pwd; \
	cmake -D CMAKE_BUILD_TYPE=Release -D ENABLE_PROGRAMS=OFF -D ENABLE_TESTING=ON -D INSTALL_MBEDTLS_HEADERS=ON -D USE_SHARED_MBEDTLS_LIBRARY=ON -D MBEDTLS_FATAL_WARNINGS=ON -D CMAKE_INSTALL_PREFIX="$(CURDIR)/downloads/mbedtls/build/compiled" ..
	$(MAKE) -C $(CURDIR)/downloads/mbedtls/build
	$(MAKE) install -C $(CURDIR)/downloads/mbedtls/build
endif

libdir:
	@echo "Check build directory exists"
ifeq ("$(wildcard $(CAUTH_BUILD_DIR))","")
	@echo "Creating $(CAUTH_BUILD_DIR_NAME) directory"
	@mkdir $(CAUTH_BUILD_DIR) -v
endif

	@echo "Check $(CAUTH_BUILD_DIR_NAME)/lib exists"
ifeq ("$(wildcard $(CAUTH_BUILD_DIR)/lib)","")
	@echo "Creating $(CAUTH_BUILD_DIR_NAME)/lib directory"
	@mkdir $(CAUTH_BUILD_DIR)/lib -v
endif

	@echo "Check $(CAUTH_BUILD_DIR_NAME)/lib/shared exists"
ifeq ("$(wildcard $(CAUTH_BUILD_DIR)/lib/shared)","")
	@echo "Creating $(CAUTH_BUILD_DIR_NAME)/lib/shared directory"
	@mkdir $(CAUTH_BUILD_DIR)/lib/shared -v
endif

	@echo "Check $(CAUTH_BUILD_DIR_NAME)/$(CAUTH_BUILD_INCLUDE_DIR_NAME) exists"
ifeq ("$(wildcard $(CAUTH_BUILD_INCLUDE_DIR))","")
	@echo "Creating $(CAUTH_BUILD_DIR_NAME)/$(CAUTH_BUILD_INCLUDE_DIR_NAME) directory"
	@mkdir $(CAUTH_BUILD_INCLUDE_DIR) -v
endif

main: libdir cyodecode_shared.o cyodecode.o mbedtls
ifeq ("$(wildcard $(CAUTH_BUILD_DIR)/lib/lib$(LIBANAME).a)","")
	@echo "Build CAuth2 object"
	@$(CC) -O2 -c src/cauth2.c -I$(MBED_INCLUDE_DIR) -I$(INCLUDEDIR) -L$(MBED_LIB_DIR) -lmbedcrypto -o cauth.o -Wall
	@echo "Build static library $(LIBANAME).a ..."
	@cp $(MBED_LIB_DIR)/$(MBED_CRYPTO_NAME) $(CAUTH_BUILD_DIR)/lib -v
	@mv $(CAUTH_BUILD_DIR)/lib/$(MBED_CRYPTO_NAME) $(CAUTH_BUILD_DIR)/lib/lib$(LIBANAME).a
	@ar -q $(CAUTH_BUILD_DIR)/lib/lib$(LIBANAME).a cauth.o cyodecode.o
else
	@echo "Nothing to do lib$(LIBANAME).a already exists"
endif

ifeq ("$(wildcard $(CAUTH_BUILD_DIR)/lib/shared/lib$(LIBANAME).so)","")
	@echo "Build CAuth2 object shared"
	pwd; cd $(MBED_LIB_OBJ_DIR); pwd; \
	$(AR) $(MBED_LIB_OBJ_DIR)/lib$(LIBANAME)_shared.a *.o; \
	cd $(CAUTH_BUILD_DIR)/lib/shared -v; pwd; \
	mv $(MBED_LIB_OBJ_DIR)/lib$(LIBANAME)_shared.a $(CAUTH_BUILD_DIR)/lib/shared -v
	@$(CC) -O2 -c $(CURDIR)/src/cauth2.c -I$(MBED_INCLUDE_DIR) -I$(INCLUDEDIR) -L$(CAUTH_BUILD_DIR)/lib/shared -l$(LIBANAME)_shared -fPIC -o cauth_shared.o -Wall
	@ar -q $(CAUTH_BUILD_DIR)/lib/shared/lib$(LIBANAME)_shared.a $(CURDIR)/cauth_shared.o $(CURDIR)/cyodecode_shared.o
	@$(CC) -shared -O2 -fPIC $(CURDIR)/src/cauth2.c -I$(INCLUDEDIR) -I$(MBED_INCLUDE_DIR) -L$(CAUTH_BUILD_DIR)/lib/shared -l$(LIBANAME)_shared -o $(CAUTH_BUILD_DIR)/lib/shared/lib$(LIBANAME).so -Wall
	@strip $(CAUTH_BUILD_DIR)/lib/shared/lib$(LIBANAME).so
else
	@echo "Nothing to do lib$(LIBANAME).so already exists"
endif

ifeq ("$(wildcard $(CAUTH_BUILD_INCLUDE_DIR)/cauth2.h)","")
	@echo "Copy include file"
	@cp $(INCLUDEDIR)/cauth2_dev.h $(CAUTH_BUILD_INCLUDE_DIR) -v
	@mv $(CAUTH_BUILD_INCLUDE_DIR)/cauth2_dev.h $(CAUTH_BUILD_INCLUDE_DIR)/cauth2.h -v
else
	@echo "Nothing to do cauth2.h file"
endif

.PHONY: test
test: main
	@echo "Execute test ..."
ifeq ("$(wildcard $(CURDIR)/test/test)","")
	@echo "Starting build tests"
	@$(CC) -O2 test/main.c src/ctest/asserts.c -I$(INCLUDEDIR)/test -I$(MBED_INCLUDE_DIR) -I$(CAUTH_BUILD_INCLUDE_DIR) -L$(CAUTH_BUILD_DIR)/lib -l$(LIBANAME) -o test/test -fsanitize=leak,address -Wall
endif
	@echo "Executing tests (static) ..."
	@$(CURDIR)/test/test
	@echo "All tests passed (static) !"
	@echo "Execute test_shared ..."
ifeq ("$(wildcard $(CURDIR)/test/test_shared)","")
	@echo "Starting build tests (shared)"
	@$(CC) -O2 test/main.c src/ctest/asserts.c -I$(INCLUDEDIR)/test -I$(MBED_INCLUDE_DIR) -I$(CAUTH_BUILD_INCLUDE_DIR) -L$(CAUTH_BUILD_DIR)/lib/shared -l$(LIBANAME) -o test/test_shared -fsanitize=leak,address -Wall
endif
	pwd; export LD_LIBRARY_PATH=$(CAUTH_BUILD_DIR)/lib/shared; \
	$(CURDIR)/test/test_shared; pwd;
	@echo "All tests passed (shared) !"

.PHONY: clean
clean:

ifneq ("$(wildcard $(CURDIR)/*.o)","")
	@echo "Removing objects ..."
	rm -v $(CURDIR)/*.o
else
	@echo "Nothing to do with objects"
endif

	@echo "Check build folder ..."
ifneq ("$(wildcard $(CURDIR)/downloads/mbedtls/build)","")
	@echo "Deleting all build folder ..."
	@rm -rfv $(CURDIR)/downloads/mbedtls/build
endif

	@echo "Check lib folder ..."
ifneq ("$(wildcard $(CAUTH_BUILD_DIR))","")
	@echo "Deleting all $(CAUTH_BUILD_DIR_NAME) folder ..."
	@rm -rfv $(CAUTH_BUILD_DIR)
endif

	@echo "Check if tests exists"
ifneq ("$(wildcard $(CURDIR)/test/test)","")
	rm -v $(CURDIR)/test/test
else
	@echo "Delete test: Nothing to do"
endif

ifneq ("$(wildcard $(CURDIR)/test/test_shared)","")
	rm -v $(CURDIR)/test/test_shared
else
	@echo "Delete test_shared: Nothing to do"
endif

.PHONY: panelauth_build
panelauth_build: test
	@python3 setup.py build

.PHONY: panelauth_install
panelauth_install: test
	@python3 setup.py install
