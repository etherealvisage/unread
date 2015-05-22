.PHONY: all
all:
	$(MAKE) -C build

.PHONY: redep
redep:
	mkdir -p build/ ; cd build/ ; cmake .. ; cd ..

.PHONY: clean
clean:
	$(MAKE) -C build clean

.PHONY: distclean
distclean:
	$(MAKE) -C build clean
	rm -rf build
