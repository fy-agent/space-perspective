#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <sys/stat.h>

// Balanced access belongs to one picker session; the UI never supplies a path.
static NSURL *selectedURL;
static BOOL accessing;

static char *reply(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
}

void sp_close_scope(void);

char *sp_pick(const char *expected) {
    @autoreleasepool {
        if (accessing) [selectedURL stopAccessingSecurityScopedResource];
        selectedURL = nil; accessing = NO;
        NSOpenPanel *panel = [NSOpenPanel openPanel];
        panel.canChooseFiles = NO; panel.canChooseDirectories = YES;
        panel.allowsMultipleSelection = NO; panel.resolvesAliases = NO;
        panel.canCreateDirectories = NO;
#ifdef SP_READ_ONLY
        panel.message = @"只查看下载文件夹内的文件名称、大小与日期。此版本没有文件处理功能。";
        panel.prompt = @"只读查看下载文件夹";
#else
        panel.message = @"本次仅可选择为桌面验证创建的临时样本文件夹。";
        panel.prompt = @"选择样本文件夹";
#endif
        panel.directoryURL = [NSURL fileURLWithPath:[NSString stringWithUTF8String:expected]];
        if ([panel runModal] != NSModalResponseOK) return reply(@{@"error": @"PICKER_CANCELLED"});
        NSURL *url = panel.URL;
        NSString *wanted = [NSString stringWithUTF8String:expected];
        if (![url.path isEqualToString:wanted]) return reply(@{@"error": @"REGISTERED_SCOPE_ONLY"});
        selectedURL = url; accessing = [url startAccessingSecurityScopedResource];
        NSError *error;
        NSURLBookmarkCreationOptions options = NSURLBookmarkCreationWithSecurityScope;
#ifdef SP_READ_ONLY
        options |= NSURLBookmarkCreationSecurityScopeAllowOnlyReadAccess;
#endif
        NSData *bookmark = [url bookmarkDataWithOptions:options includingResourceValuesForKeys:nil relativeToURL:nil error:&error];
        if (!bookmark) {
            BOOL started = accessing;
            if (accessing) [url stopAccessingSecurityScopedResource];
            selectedURL = nil; accessing = NO;
            return reply(@{@"error": @"BOOKMARK_CREATE_FAILED", @"native_code": @(error.code), @"native_domain":error.domain ?: @"", @"native_reason":error.localizedDescription ?: @"", @"started_access":@(started)});
        }
        BOOL stale = NO;
        NSURL *resolved = [NSURL URLByResolvingBookmarkData:bookmark options:NSURLBookmarkResolutionWithSecurityScope | NSURLBookmarkResolutionWithoutUI relativeToURL:nil bookmarkDataIsStale:&stale error:&error];
        if (!resolved || stale || !accessing) { sp_close_scope(); return reply(@{@"error": @"BOOKMARK_INVALID"}); }
        return reply(@{@"path": url.path, @"bookmark_created": @YES, @"bookmark_resolved": (resolved != nil && !stale) ? @YES : @NO, @"bookmark_stale": @(stale), @"bookmark_error_code": @(error.code), @"bookmark_error_domain": error.domain ?: @"", @"started_access": @(accessing)});
    }
}

void sp_close_scope(void) {
    if (accessing) [selectedURL stopAccessingSecurityScopedResource];
    selectedURL = nil; accessing = NO;
}

// Final identity check runs inside a coordinated native move. No content reads.
#ifndef SP_READ_ONLY
char *sp_trash(const char *path, unsigned long long dev, unsigned long long ino, unsigned long long size, long long mtime_sec, long long mtime_nsec, long long ctime_sec, long long ctime_nsec) {
    @autoreleasepool {
        NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
        __block NSDictionary *result;
        NSError *coordError;
        NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
        [coordinator coordinateWritingItemAtURL:url options:NSFileCoordinatorWritingForMoving error:&coordError byAccessor:^(NSURL *target) {
            struct stat info;
            if (lstat(target.fileSystemRepresentation, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
                (unsigned long long)info.st_dev != dev || info.st_ino != ino || (unsigned long long)info.st_size != size ||
                info.st_mtimespec.tv_sec != mtime_sec || info.st_mtimespec.tv_nsec != mtime_nsec ||
                info.st_ctimespec.tv_sec != ctime_sec || info.st_ctimespec.tv_nsec != ctime_nsec) {
                result = @{@"error": @"FILE_DRIFT"}; return;
            }
            NSURL *trashed = nil; NSError *error;
            BOOL ok = [[NSFileManager defaultManager] trashItemAtURL:target resultingItemURL:&trashed error:&error];
            if (!ok) { result = @{@"error": @"TRASH_FAILED", @"native_code": @(error.code)}; return; }
            result = @{@"trash_path": trashed.path ?: @"", @"status": @"trashed"};
        }];
        return reply(result ?: @{@"error": @"COORDINATION_FAILED", @"native_code": @(coordError.code)});
    }
}
#endif
