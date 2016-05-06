all: redablooms

clean:
	$(MAKE) -C src clean

.PHONY: redablooms
redablooms:
	$(MAKE) -C src
