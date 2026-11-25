# top level Makefile for mavis
# (C) 1997-2011 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= mavis
OD	= $(BASE)/build/$(OS)$(GITBRANCH_EXT)/$(PROG)

all: build perl_build python_build

$(OD):
	@mkdir -p "$@"

$(OD)/token.h: $(BASE)/mavis/token.pl | $(OD)
	@rm -f "$(BASE)/mavis/token.h" "$(BASE)/mavis/token.c"
	@perl "$^" $(OD)

env: $(OD)

build:	env $(OD)/token.h
	@$(MAKE) -f "$(BASE)/$(PROG)/Makefile.obj" -C "$(OD)" "BASE=$(BASE)"

install: perl_install $(OD)/token.h
	@$(MAKE) -f "$(BASE)/$(PROG)/Makefile.obj" -C "$(OD)" "BASE=$(BASE)" install

clean:
	@rm -rf "$(OD)" *~ core *.BAK

perl_build:
	@$(MAKE) -C perl "BASE=$(BASE)"

perl_install:
	@$(MAKE) -C perl "BASE=$(BASE)" install

python_build:
	@$(MAKE) -C python "BASE=$(BASE)"

python_install:
	@$(MAKE) -C python "BASE=$(BASE)" install

