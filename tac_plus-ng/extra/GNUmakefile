include $(BASE)/Makefile.inc

S = etc_init.d_tac_plus-ng
E = $(INSTALLROOT)$(LIBARCHDIR_DEST)/mavis/extra

all: $(S)

$(S): ../../spawnd/extra/etc_init.d_spawnd
	-sed 's/spawnd/tac_plus-ng/-ngg'< $^ > $@

$(E)/$(S): $(S) | $(E)
	$(INSTALL) -m 0755 $^ $@

$(E):
	@mkdir -p -m 0755 $@

$(INSTALLROOT)$(SBINDIR_DEST):
	@mkdir -p -m 0755 $@

$(E)/de.pro-bono-publico.tac_plus-ng.plist: de.pro-bono-publico.tac_plus-ng.plist | $(E)
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus-ng.cfg-ads: tac_plus-ng.cfg-ads | $(E)
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus-ng.service: tac_plus-ng.service | $(E)
	$(INSTALL) -m 0644 $^ $@

$(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl: tacspooflog.pl | $(INSTALLROOT)$(SBINDIR_DEST)
	$(INSTALL) -m 0755 $^ $@

install: $(E) $(E)/$(S) $(E)/de.pro-bono-publico.tac_plus-ng.plist $(E)/etc_init.d_tac_plus-ng $(E)/tac_plus-ng.cfg-ads $(E)/tac_plus-ng.service $(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl

