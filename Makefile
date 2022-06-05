CC=gcc
STRIP=strip
INCLUDEDIR=$(PWD)/include/
CURDIR=$(PWD)

all: main

cyodecode.o: src/CyoDecode.c src/CyoEncode.c
	@echo "Build Base32 Utilities object"
	@$(CC) -O2 -c src/CyoDecode.c -Iinclude -fPIC -o cyodecode.o -Wall

cauth.o: src/cauth2.c
	@echo "Build CAuth2 object"
	@$(CC) -O2 -c src/cauth2.c -Iinclude -Llib -lnanocrypto1 -fPIC -o cauth.o -Wall

main: cyodecode.o cauth.o
	@echo "Do nothing for a while ..."

.PHONY: test
test: main
	@echo "Execute test ..."
ifeq ("$(wildcard $(CURDIR)/test/test)","")
	@echo "Starting build tests"
	@$(CC) -O2 test/main.c src/cauth2.c src/CyoDecode.c src/ctest/asserts.c -I$(INCLUDEDIR) -Llib -lnanocrypto1 -o test/test -fsanitize=leak,address -Wall
endif
	@echo "Executing tests ..."
	@$(CURDIR)/test/test
	@echo "All tests passed !"

.PHONY: clean
clean:

ifneq ("$(wildcard $(CURDIR)/*.o)","")
	@echo "Removing objects ..."
	rm -v $(CURDIR)/*.o
else
	@echo "Nothing to do with objects"
endif

	@echo "Check if tests exists"
ifneq ("$(wildcard $(CURDIR)/test/test)","")
	rm -v $(CURDIR)/test/test
else
	@echo "Nothing to do"
endif
