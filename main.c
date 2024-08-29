#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/ldsyms.h>
#include "treblehook/treblehook.h"

static bool g_test_interpose_1st_party_framework = false;
static bool g_test_interpose_exe_interposing_1st_party = false;

typedef struct kevent_qos_s *kevent_qos_t;

int (*og_kevent_qos)(int kq,
                     const kevent_qos_t changelist, int nchanges,
                     struct kevent_qos_s *eventlist, int nevents,
                     void *data_out, size_t *data_available,
                     unsigned int flags) = NULL;
char  *(*og_getenv)(const char *) = NULL;
CFTypeRef _Nullable
(*og_objc_msgSend)(CFTypeRef _Nullable self, const char* _Nonnull op, CFTypeRef arg1, CFTypeRef arg2, CFTypeRef arg3, CFTypeRef arg4, CFTypeRef arg5, CFTypeRef arg6, ...) = NULL;

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
  g_test_interpose_1st_party_framework = true;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    printf("- kevent_qos|libdispatch.dylib: system dylib interposing succeeded\n");
  });
  return og_kevent_qos(kq, changelist, nchanges, eventlist, nevents, data_out, data_available, flags);
}

#define CUSTOM_ENV "CAT_FARTS_MEOW_MEOW"
char *my_getenv(const char *env) {
  return CUSTOM_ENV;
}

CFTypeRef _Nullable
my_objc_msgSend(CFTypeRef _Nullable self, const char* _Nonnull op, CFTypeRef arg1, CFTypeRef arg2, CFTypeRef arg3, CFTypeRef arg4, CFTypeRef arg5, CFTypeRef arg6, ...) {
  va_list args;
  va_start(args, arg6);
  CFTypeRef result = og_objc_msgSend(self, op, arg1, arg2, arg3, arg4, arg5, arg6, args);
  va_end(args);
  return result;
}

int main(int argc, const char * argv[]) {
  
  extern const struct mach_header *dyld_image_header_containing_address(const void* addr);
  const struct mach_header *dispatch_header = dyld_image_header_containing_address(dispatch_main);
  
  struct rebinding binds[3] = {{"kevent_qos", my_kevent_qos, (void*)&og_kevent_qos},
                              {"getenv", my_getenv, (void*)&og_getenv},
                              {"objc_msgSend$defaultManager", my_objc_msgSend, (void*)&og_objc_msgSend}};
  printf("Running tests, attempting to interpose...\n");
  
  assert(rebind_symbols_4_image((void*)dispatch_header, &binds[0], 1) == 0); // kevent
  assert(rebind_symbols_4_image((void*)&_mh_execute_header, &binds[1], 1) == 0); // getenv
#if 0
  // work in progress
  assert(rebind_symbols_4_image((void*)&_mh_execute_header, &binds[2], 1) == 0); // objc_msgSend
  [[NSFileManager defaultManager] fileExistsAtPath:@"hi"];
#endif
  
  const char *path = getenv("PATH");
  if (!strcmp(CUSTOM_ENV, path)) {
    printf("- getenv|_mh_execute_header: system dylib interposing succeeded\n");
    g_test_interpose_exe_interposing_1st_party = true;
  }
  
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
  dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0 * NSEC_PER_SEC);
  dispatch_source_set_event_handler(timer, ^{});
  dispatch_activate(timer);
  
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    assert(g_test_interpose_1st_party_framework);
    assert(g_test_interpose_exe_interposing_1st_party);
    exit(0);
  });
  dispatch_main();
  return 0;
}
