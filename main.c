
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
  rebind_symbols_4_image((void*)header, binds, 1);
  
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
  dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0 * NSEC_PER_SEC);
  dispatch_source_set_event_handler(timer, ^{
    printf("yo whatup\n");
  });
  
  dispatch_activate(timer);
  dispatch_main();
  return 0;
}
