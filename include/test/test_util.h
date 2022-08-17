#ifndef TEST_UTIL_H
 #define TEST_UTIL_H

#include <stdio.h>
#include <stdint.h>

int gen_rand_no_entropy_util(uint8_t *, size_t, int *, void *);
int test_vector(uint8_t *, size_t, uint8_t);

const char *CONST_STR_TEST[]={
    "Hey !!", "Test 123", "TEST", "TEST 123", "This is a text", "Testing test string", "0123456789", "Bitcoin", "BITCOIN",
    "Buy Bitcoin", "BUY BITCOIN", "C is a very cool language", "Linux", "Simple text ~ ç` àá&1928", "VLSI world", "transistor",
    "", "Empty", "Main text", "Source code", "Hello World", "HELLO WORLD", "Santos Dummond", "Tesla, Nikola",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890", "Blá blá, blá", "Linux inside here", "IoT", "Embedded systems",
    "CTest is amazing !!!", "C is powerful",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum"
};

const char *CONST_STR_TEST_2[]={
    "Testing const string", "123", "456", "7890", "ABC", "XYZ", "???Á[[s]]2881*(81876***(938 txt",
    "Any text goes here", "Blochain", "Cryptocurrency", "We love C", "C is faster", "We love assembly",
    "Satoshi", "Nakamoto Satoshi", "Einstein", "We love physics", "Control panel", "Panel auth2",
    "Liberty", "Hi Tech", "Cryptography is cool", "GNU World", "Private property in mankind", "Unix is beautiful",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Id nibh tortor id aliquet lectus proin. Fermentum leo vel orci porta non pulvinar neque. Integer feugiat scelerisque varius morbi enim nunc faucibus. Mattis enim ut tellus elementum sagittis vitae et. Egestas diam in arcu cursus euismod quis viverra nibh. Condimentum id venenatis a condimentum. Malesuada bibendum arcu vitae elementum curabitur vitae nunc sed velit. Proin sed libero enim sed faucibus. Suspendisse interdum consectetur libero id faucibus nisl tincidunt. Feugiat nisl pretium fusce id velit ut tortor. Elementum integer enim neque volutpat ac tincidunt vitae. Feugiat nisl pretium fusce id velit ut tortor pretium viverra. Bibendum at varius vel pharetra vel. Eu consequat ac felis donec et odio pellentesque diam. Cras ornare arcu dui vivamus arcu. Orci ac auctor augue mauris. Vel facilisis volutpat est velit egestas dui id ornare.",
    "myTeslaSMPS is a cute switching mode power supply", "Lightning network", "Proof of Work"
};

const char *CONST_STR_TEST_3[]={
    "Another text allocated dynamically", "ijklm", "abc", "DEF", "Hello dynamic", "Smart contracts", "Defi",
    ";)", "^__^", "hey there", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent quis leo nunc. Mauris vulputate, erat ut tempus varius, felis sem ultricies ante, in suscipit nisi diam ut orci. Aenean sollicitudin condimentum felis at placerat. Morbi iaculis elit libero, a elementum lacus varius a. Quisque semper lectus sed justo aliquam, ut sodales lorem molestie. Morbi ullamcorper neque vel dui pellentesque mattis. Nulla rutrum mi vitae est fringilla iaculis. Cras ullamcorper, nulla in sagittis ultricies, velit augue eleifend nisi, a finibus purus ipsum ac nibh. Suspendisse in lobortis arcu, id condimentum risus. Praesent pellentesque velit eget arcu lobortis hendrerit. Duis posuere sapien feugiat, placerat velit vel, vulputate libero. Donec nec purus sit amet tellus posuere vehicula. Integer ullamcorper ex diam, vitae ultrices felis varius eget.\
Maecenas sagittis erat id lacus finibus interdum. Curabitur venenatis, quam convallis fermentum placerat, eros sapien efficitur nulla, vel congue tellus augue non neque. Nam luctus augue id bibendum venenatis. Aenean fringilla, eros non interdum fringilla, nibh nunc consequat ipsum, auctor iaculis justo nisl eu lacus. Nullam ut commodo ipsum. Duis scelerisque tortor vitae elit placerat, a viverra diam faucibus. Ut in augue quis eros venenatis dapibus. Nunc dictum vitae elit vel dignissim. Integer eu quam vitae risus ultrices accumsan ac at est. In euismod in felis id lobortis. Aenean sem massa, feugiat eu imperdiet a, rhoncus at purus. Nullam non mattis nulla. Nunc eu ornare orci, in lobortis turpis.\
Aenean at vestibulum felis. Nulla facilisi. Fusce vel quam nisl. Morbi a elit hendrerit, vehicula orci vel, aliquet metus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque pretium dolor arcu, gravida elementum augue venenatis sollicitudin. Maecenas cursus fermentum augue, vitae mattis turpis eleifend blandit. In nisi nisi, ultrices non auctor sed, aliquam non ligula. Sed ullamcorper quam pulvinar diam condimentum, vitae tempus neque lacinia. Integer ut mi vitae leo tincidunt porttitor. Nunc tincidunt tincidunt sagittis. Aliquam sem leo, dignissim vel placerat tempus, rutrum ut nisi. Morbi accumsan posuere luctus. Donec velit eros, bibendum et lectus sit amet, imperdiet consequat quam. Pellentesque faucibus dolor tellus, ac consequat ipsum tempus ac. Vestibulum libero ex, pulvinar non gravida eu, condimentum at urna.\
Aenean semper accumsan volutpat. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nunc quis purus at augue fringilla varius. Nunc efficitur odio quis pulvinar euismod. Integer laoreet tempus aliquam. Ut nec turpis urna. Aliquam id tempus velit.\
Curabitur erat leo, iaculis porttitor facilisis et, mollis id quam. Donec consectetur volutpat felis sit amet sodales. Integer rutrum nisl sed malesuada tristique. Donec pretium purus feugiat, efficitur ante id, consequat mi. Integer non turpis sapien. Quisque a euismod dui, at malesuada ligula. In hac habitasse platea dictumst. Ut id dolor suscipit, aliquam leo at, tempor dolor. Donec molestie leo urna, eget condimentum mi fringilla sit amet. Donec ac est rhoncus, efficitur augue eu, efficitur felis. Ut interdum egestas auctor.\
Maecenas mattis in ipsum eget condimentum. Morbi gravida purus sit amet odio tincidunt consequat. Donec rutrum odio ut dolor tincidunt dapibus. Nunc eget sollicitudin magna. Sed tristique, eros vel pharetra laoreet, magna arcu aliquet nulla, eu suscipit est nulla vitae massa. Proin at justo eget ligula suscipit mollis placerat non leo. Vestibulum congue turpis nunc, a dignissim metus scelerisque eget. Sed a nisi neque. Cras nec turpis ante. Suspendisse vitae luctus lorem, vitae suscipit ante. In et nibh at elit sodales sollicitudin. Nullam vitae mi aliquam, imperdiet diam eget, varius justo.\
Fusce rhoncus sodales maximus. Duis imperdiet aliquam mi ac fermentum. Nulla facilisi. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus non tortor pharetra, lacinia purus nec, condimentum sapien. Curabitur metus massa, lacinia nec leo quis, euismod lacinia erat. Fusce vitae tincidunt libero, non pulvinar enim. Aliquam at consectetur nisi. Etiam ac volutpat quam. Suspendisse nec metus id arcu ornare convallis at et dolor. Donec facilisis nisi orci, et pulvinar nunc egestas ac. Sed mattis iaculis dolor, vel hendrerit lacus ultricies eu. Vivamus ac massa consectetur, commodo justo at, imperdiet nunc. Praesent ipsum nisl, pharetra tempus dapibus ut, rutrum in lorem. Mauris ac tincidunt ante.\
Proin egestas, elit nec mattis tristique, nisi ex viverra velit, eget consectetur dui massa eget nisi. Pellentesque gravida, tellus ut ultricies fringilla, est nisl pretium erat, et rhoncus urna nisl vel est. Praesent volutpat convallis erat vitae facilisis. Donec convallis elit arcu, id sollicitudin dui fringilla et. Morbi tristique diam ac diam tristique, dictum aliquet erat sagittis. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Aenean tincidunt, neque vel blandit suscipit, risus lorem faucibus orci, et sollicitudin tortor turpis vestibulum est. Sed neque nunc, interdum sit amet luctus id, posuere dignissim metus. Morbi mattis interdum auctor."
};

#define CONST_STR_TEST_ELEMENTS (sizeof(CONST_STR_TEST)/sizeof(CONST_STR_TEST[0]))
#define CONST_STR_TEST_ELEMENTS_2 (sizeof(CONST_STR_TEST_2)/sizeof(CONST_STR_TEST_2[0]))
#define CONST_STR_TEST_ELEMENTS_3 (sizeof(CONST_STR_TEST_3)/sizeof(CONST_STR_TEST_3[0]))

#endif