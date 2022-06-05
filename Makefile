CC=gcc
STRIP=strip
INCLUDEDIR=$(PWD)/include/
CURDIR=$(PWD)

all: main

main:
	@echo "Do nothing for a while ..."

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
	@echo "Check if tests exists"
ifneq ("$(wildcard $(CURDIR)/test/test)","")
	rm -v $(CURDIR)/test/test
else
	@echo "Nothing to do"
endif
