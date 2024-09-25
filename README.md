# treblehook

treblehook is a sloopy improvement on FB's fishhook and is designed specifically for arm64/arm64e. treblehook will allow you to intercept symbol calls across libraries & frameworks.

__fishhook__ is a very simple library that enables dynamically rebinding symbols in Mach-O binaries running on iOS in the simulator and on device. This provides functionality that is similar to using [`DYLD_INTERPOSE`][interpose] on OS X. At Facebook, we've found it useful as a way to hook calls in libSystem for debugging/tracing purposes (for example, auditing for double-close issues with file descriptors).

[interpose]: http://opensource.apple.com/source/dyld/dyld-210.2.3/include/mach-o/dyld-interposing.h "<mach-o/dyld-interposing.h>"

## Usage

Once you add `treblehook.h`/`treblehook.c` to your project, you can rebind symbols as follows:
```Objective-C

#include <CoreFoundation/CoreFoundation.h>
#include "treblehook/treblehook.h"

typedef struct kevent_qos_s *kevent_qos_t;
int (*og_kevent_qos)(int kq,
                     const kevent_qos_t changelist, int nchanges,
                     struct kevent_qos_s *eventlist, int nevents,
                     void *data_out, size_t *data_available,
                     unsigned int flags);
extern int kevent_qos(int kq,
                          const struct kevent_qos_s *changelist, int nchanges,
                          struct kevent_qos_s *eventlist, int nevents,
                          void *data_out, size_t *data_available,
                          unsigned int flags);
int my_kevent_qos(int kq,
                      const kevent_qos_t changelist, int nchanges,
                      kevent_qos_t eventlist, int nevents,
                      void *data_out, size_t *data_available,
                      unsigned int flags) {
  return og_kevent_qos(kq, changelist, nchanges, eventlist, nevents, data_out, data_available, flags);
}


int main(int argc, const char * argv[]) {
  
  extern const struct mach_header* dyld_image_header_containing_address(const void* addr);
  const struct mach_header*  header = dyld_image_header_containing_address(dispatch_main);
  struct rebinding binds[1] = {{"kevent_qos", my_kevent_qos, (void*)&og_kevent_qos}};
  rebind_dsc_direct_symbols_image((void*)header, binds, 1);
  
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
  dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0 * NSEC_PER_SEC);
  dispatch_source_set_event_handler(timer, ^{
    printf("yo whatup\n");
  });
  
  dispatch_activate(timer);
  dispatch_main();
  return 0;
}

```


## How it works

Slightly dated, but read [this symbol interposing writeup](https://github.com/DerekSelander/symbol-interposing?tab=readme-ov-file#symbol-binding-detour). trebelhook will attempt to rebind symbols in certain memory segments that could be made into R/W.  If that fails (likely because that page can be mapped to a file on disk), treblehook will attempt to modify executable code. As a result treblehook should only be used in code that has the `com.apple.security.cs.allow-unsigned-executable-memory`, is being debugged, or is not signed at all in order to allow treblehook to run invalid pages of memory should it be required to rebind executable memory.


### Old Fishhook How it works writeup 

`dyld` binds lazy and non-lazy symbols by updating pointers in particular sections of the `__DATA` segment of a Mach-O binary. __fishhook__ re-binds these symbols by determining the locations to update for each of the symbol names passed to `rebind_symbols` and then writing out the corresponding replacements.

For a given image, the `__DATA` segment may contain two sections that are relevant for dynamic symbol bindings: `__nl_symbol_ptr` and `__la_symbol_ptr`. `__nl_symbol_ptr` is an array of pointers to non-lazily bound data (these are bound at the time a library is loaded) and `__la_symbol_ptr` is an array of pointers to imported functions that is generally filled by a routine called `dyld_stub_binder` during the first call to that symbol (it's also possible to tell `dyld` to bind these at launch). In order to find the name of the symbol that corresponds to a particular location in one of these sections, we have to jump through several layers of indirection. For the two relevant sections, the section headers (`struct section`s from `<mach-o/loader.h>`) provide an offset (in the `reserved1` field) into what is known as the indirect symbol table. The indirect symbol table, which is located in the `__LINKEDIT` segment of the binary, is just an array of indexes into the symbol table (also in `__LINKEDIT`) whose order is identical to that of the pointers in the non-lazy and lazy symbol sections. So, given `struct section nl_symbol_ptr`, the corresponding index in the symbol table of the first address in that section is `indirect_symbol_table[nl_symbol_ptr->reserved1]`. The symbol table itself is an array of `struct nlist`s (see `<mach-o/nlist.h>`), and each `nlist` contains an index into the string table in `__LINKEDIT` which where the actual symbol names are stored. So, for each pointer `__nl_symbol_ptr` and `__la_symbol_ptr`, we are able to find the corresponding symbol and then the corresponding string to compare against the requested symbol names, and if there is a match, we replace the pointer in the section with the replacement.

The process of looking up the name of a given entry in the lazy or non-lazy pointer tables looks like this:
![Visual explanation](http://i.imgur.com/HVXqHCz.png)
