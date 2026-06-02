#import <Cocoa/Cocoa.h>

static void (*g_openCallback)(const char*) = nullptr;

@interface FileOpenHandler : NSObject
@end

@implementation FileOpenHandler
- (void)handleOpenFiles:(NSAppleEventDescriptor *)event
         withReplyEvent:(NSAppleEventDescriptor *)reply {
    (void)reply;
    NSAppleEventDescriptor *list =
        [event paramDescriptorForKeyword:keyDirectObject];
    NSInteger count = [list numberOfItems];
    for (NSInteger i = 1; i <= count; i++) {
        NSAppleEventDescriptor *item = [list descriptorAtIndex:i];
        NSString *urlStr = [item stringValue];
        if (!urlStr) continue;
        NSURL *url = [NSURL URLWithString:urlStr];
        if (!url || !url.path) continue;
        if (g_openCallback) {
            g_openCallback([url.path UTF8String]);
        }
    }
}
@end

extern "C" void macos_register_open_handler(void (*callback)(const char*)) {
    g_openCallback = callback;
    static FileOpenHandler *handler = [[FileOpenHandler alloc] init];
    [[NSAppleEventManager sharedAppleEventManager]
        setEventHandler:handler
        andSelector:@selector(handleOpenFiles:withReplyEvent:)
        forEventClass:kCoreEventClass
        andEventID:kAEOpenDocuments];
    [NSApp activateIgnoringOtherApps:YES];
}

extern "C" const char* macos_open_file_dialog(void) {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.title = @"Select Manifest File";
    panel.allowedFileTypes = @[@"json", @"txt"];
    if ([panel runModal] == NSModalResponseOK) {
        NSString *path = panel.URL.path;
        return strdup([path UTF8String]);
    }
    return nullptr;
}
