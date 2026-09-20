#import <AppKit/AppKit.h>

extern char *sp_dispatch(const char *, const char *);
extern void sp_release(char *);

static NSDictionary *call(NSString *command, NSDictionary *args) {
    NSData *input = [NSJSONSerialization dataWithJSONObject:args options:0 error:nil];
    NSString *text = [[NSString alloc] initWithData:input encoding:NSUTF8StringEncoding];
    char *raw = sp_dispatch(command.UTF8String, text.UTF8String);
    NSData *output = [[NSString stringWithUTF8String:raw] dataUsingEncoding:NSUTF8StringEncoding];
    sp_release(raw);
    return [NSJSONSerialization JSONObjectWithData:output options:0 error:nil];
}
static id optional(id value) { return value == NSNull.null ? nil : value; }
static NSString *message(NSString *code) {
    return @{
        @"PICKER_CANCELLED": @"已取消选择，之前的选择与操作预览已失效。",
        @"FIXTURE_ONLY": @"本次只支持已注册的样本文件夹，请重新选择。",
        @"REGISTERED_SCOPE_ONLY": @"请选择本次测试指定的文件夹。",
        @"READ_ONLY_MODE": @"本次仅供查看，文件处理功能不可用。",
        @"ADVICE_PROTECTED": @"这项建议保留或先判断，不加入清理预览。",
        @"KEEP_REFERENCE": @"请先保留对照文件，不能把相互对照的两份都加入清理预览。",
        @"PROTECTED_ITEM": @"这项包含重要资料线索，已保留。",
        @"FILE_DRIFT": @"文件在预览后发生变化，未执行。请重新扫描。",
        @"TRASH_FILE_DRIFT": @"废纸篓中的文件属性发生变化，已停止恢复。操作记录已保留。",
        @"RESTORE_CONFLICT": @"原位置已有同名文件，未覆盖。请先处理冲突再重试。",
        @"RESTORE_PERMISSION_DENIED": @"当前无法访问恢复位置，操作记录已保留。",
        @"RECONCILIATION_REQUIRED": @"上次操作中断，结果尚待核实。已暂停新的处理，操作记录已保留。",
        @"SCOPE_REQUIRED": @"请先选择样本文件夹。",
        @"PREVIEW_REQUIRED": @"请重新选择文件并查看预览。",
        @"FILE_UNAVAILABLE": @"文件当前不可访问，操作记录已保留。",
        @"SCOPE_DRIFT": @"所选文件夹发生变化，请重新选择。",
        @"BOOKMARK_INVALID": @"目录授权未完成，请重新选择。"
    }[code] ?: [@"操作未完成，文件处理已停止。记录：" stringByAppendingString:code ?: @"未知错误"];
}

@interface SPWindow : NSObject <NSApplicationDelegate, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate>
@property NSWindow *window;
@property NSTableView *table;
@property NSTextField *summary, *notice, *previewText, *receiptText;
@property NSButton *choose, *scan, *preview, *confirm, *cancel, *undo, *releaseScope;
@property NSPopUpButton *receipts;
@property NSDictionary *state;
@property NSArray *items;
@property NSString *selectedID, *receiptID;
@property BOOL readOnly;
@property NSDateFormatter *dates;
@property NSArray<NSButton *> *adviceGroups;
@property NSPopUpButton *categoryFilter;
@property NSTextView *adviceDetail;
@property NSButton *consider, *keep, *resetDecision, *review;
@property NSString *adviceGroup;
@end

@implementation SPWindow
- (NSTextField *)label:(NSString *)text size:(CGFloat)size weight:(NSFontWeight)weight {
    NSTextField *view = [NSTextField wrappingLabelWithString:text];
    view.font = [NSFont systemFontOfSize:size weight:weight];
    view.textColor = NSColor.labelColor;
    return view;
}
- (NSButton *)button:(NSString *)title action:(SEL)action {
    NSButton *button = [NSButton buttonWithTitle:title target:self action:action];
    button.bezelStyle = NSBezelStyleRounded;
    button.accessibilityLabel = title;
    return button;
}
- (NSStackView *)row:(NSArray *)views {
    NSStackView *row = [NSStackView stackViewWithViews:views];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 8;
    row.alignment = NSLayoutAttributeCenterY;
    return row;
}
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    self.readOnly = [call(@"status",@{})[@"data"][@"read_only"] boolValue];
    self.dates = [[NSDateFormatter alloc] init];
    self.dates.dateStyle = NSDateFormatterMediumStyle;
    self.dates.timeStyle = NSDateFormatterNoStyle;
    self.window = [[NSWindow alloc] initWithContentRect:self.readOnly ? NSMakeRect(0,0,900,820) : NSMakeRect(0,0,820,720)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title = self.readOnly ? @"空间透视 · 下载文件夹整理建议" : @"空间透视 · 样本验证";
    self.window.minSize = self.readOnly ? NSMakeSize(850,780) : NSMakeSize(780,680);
    self.window.delegate = self;
    self.window.releasedWhenClosed = NO;
    // Native utility tokens: system background/text, blue accent, SF, 8/16/24 spacing.
    self.window.backgroundColor = NSColor.windowBackgroundColor;
    NSStackView *stack = [NSStackView stackViewWithViews:@[]];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    stack.alignment = NSLayoutAttributeLeading;
    stack.spacing = self.readOnly ? 12 : 16;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.window.contentView addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:self.window.contentView.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:self.window.contentView.trailingAnchor constant:-24],
        [stack.topAnchor constraintEqualToAnchor:self.window.contentView.topAnchor constant:24],
        [stack.bottomAnchor constraintEqualToAnchor:self.window.contentView.bottomAnchor constant:-24]
    ]];
    [stack addArrangedSubview:[self label:self.readOnly ? @"先看哪些值得清理" : @"先看看，再决定" size:25 weight:NSFontWeightSemibold]];
    NSTextField *intro = [self label:self.readOnly ? @"先看清理、归档和保留建议，再查看每项依据。这次只做预览，文件保持原位。" : @"只查看样本的名称、大小与日期。每次处理一项，可从操作记录尝试恢复。" size:13 weight:NSFontWeightRegular];
    intro.textColor = NSColor.secondaryLabelColor;
    [stack addArrangedSubview:intro];
    self.choose = [self button:self.readOnly ? @"选择下载文件夹…" : @"选择样本文件夹…" action:@selector(chooseFolder:)];
    self.scan = [self button:self.readOnly ? @"分析并生成建议" : @"只读扫描" action:@selector(scanFolder:)];
    self.releaseScope = [self button:@"结束目录访问" action:@selector(closeScope:)];
    [stack addArrangedSubview:[self row:@[self.choose,self.scan,self.releaseScope]]];
    self.summary = [self label:@"请选择本次验证的样本文件夹。" size:13 weight:NSFontWeightMedium];
    [stack addArrangedSubview:self.summary];
    if (self.readOnly) {
        NSMutableArray *groups=[NSMutableArray array];
        for (NSString *title in @[@"建议清理",@"建议归档",@"重要资料",@"建议保留",@"需要判断"]) {
            NSButton *b=[self button:title action:@selector(selectAdviceGroup:)];
            b.tag=groups.count; b.buttonType=NSButtonTypeToggle; b.bezelStyle=NSBezelStyleRegularSquare;
            b.font=[NSFont systemFontOfSize:12 weight:NSFontWeightMedium];
            b.cell.wraps=YES;
            [b.heightAnchor constraintEqualToConstant:48].active=YES;
            [groups addObject:b];
        }
        self.adviceGroups=groups;
        NSStackView *cards=[self row:groups]; cards.distribution=NSStackViewDistributionFillEqually;
        [stack addArrangedSubview:cards];[cards.widthAnchor constraintEqualToAnchor:stack.widthAnchor].active=YES;
        self.categoryFilter=[[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
        [self.categoryFilter.widthAnchor constraintGreaterThanOrEqualToConstant:280].active=YES;
        self.categoryFilter.target=self;self.categoryFilter.action=@selector(filterAdvice:);
        [stack addArrangedSubview:[self row:@[[self label:@"文件分类" size:12 weight:NSFontWeightMedium],self.categoryFilter]]];
    }
    self.table = [[NSTableView alloc] init];
    self.table.delegate = self; self.table.dataSource = self;
    self.table.rowHeight = self.readOnly ? 60 : 56; self.table.usesAlternatingRowBackgroundColors = YES;
    self.table.allowsMultipleSelection = NO; self.table.allowsEmptySelection = YES;
    self.table.selectionHighlightStyle = self.readOnly ? NSTableViewSelectionHighlightStyleRegular : NSTableViewSelectionHighlightStyleNone;
    for (NSDictionary *spec in @[@{@"id":@"pick",@"title":@"选择",@"width":@48},
                                 @{@"id":@"name",@"title":@"文件与理由",@"width":@582},
                                 @{@"id":@"bytes",@"title":@"大小",@"width":@100}]) {
        if (self.readOnly && [spec[@"id"] isEqual:@"pick"]) continue;
        NSTableColumn *column = [[NSTableColumn alloc] initWithIdentifier:spec[@"id"]];
        column.title = spec[@"title"]; column.width = [spec[@"width"] doubleValue];
        if (self.readOnly && [column.identifier isEqual:@"name"]) { column.title = @"建议、文件与依据（点选查看详情）"; column.width = 724; }
        [self.table addTableColumn:column];
    }
    NSScrollView *scroll = [[NSScrollView alloc] init];
    scroll.documentView = self.table; scroll.hasVerticalScroller = YES;
    scroll.borderType = NSBezelBorder;
    [stack addArrangedSubview:scroll];
    [scroll.widthAnchor constraintEqualToAnchor:stack.widthAnchor].active = YES;
    [scroll.heightAnchor constraintGreaterThanOrEqualToConstant:200].active = YES;
    if (self.readOnly) {
        NSScrollView *details=[[NSScrollView alloc] init];
        details.hasVerticalScroller=YES; details.borderType=NSBezelBorder;
        self.adviceDetail=[[NSTextView alloc] initWithFrame:NSMakeRect(0,0,820,148)];
        self.adviceDetail.editable=NO;self.adviceDetail.selectable=YES;
        self.adviceDetail.font=[NSFont systemFontOfSize:12];
        self.adviceDetail.textColor=NSColor.labelColor;
        self.adviceDetail.textContainerInset=NSMakeSize(8,8);
        self.adviceDetail.autoresizingMask=NSViewWidthSizable;
        self.adviceDetail.textContainer.widthTracksTextView=YES;
        details.documentView=self.adviceDetail;
        [stack addArrangedSubview:details];
        [details.heightAnchor constraintEqualToConstant:148].active=YES;
        [details.widthAnchor constraintEqualToAnchor:stack.widthAnchor].active=YES;
        self.consider=[self button:@"加入清理预览" action:@selector(considerAdvice:)];
        self.keep=[self button:@"记为保留" action:@selector(keepAdvice:)];
        self.resetDecision=[self button:@"撤销本项决定" action:@selector(resetAdvice:)];
        self.review=[self button:@"查看清理预览（0）" action:@selector(reviewAdvice:)];
        self.review.contentTintColor=NSColor.systemBlueColor;
        [stack addArrangedSubview:[self row:@[self.consider,self.keep,self.resetDecision,self.review]]];
    }
    if (!self.readOnly) {
    self.preview = [self button:@"预览所选文件" action:@selector(previewItem:)];
    self.confirm = [self button:@"确认移到废纸篓" action:@selector(confirmPlan:)];
    self.confirm.contentTintColor = NSColor.systemBlueColor;
    self.cancel = [self button:@"取消预览" action:@selector(cancelPreview:)];
    [stack addArrangedSubview:[self row:@[self.preview,self.confirm,self.cancel]]];
    self.previewText = [self label:@"默认不选任何文件。勾选一项后，可以先查看操作预览。" size:12 weight:NSFontWeightRegular];
    [stack addArrangedSubview:self.previewText];
    [self.previewText.heightAnchor constraintGreaterThanOrEqualToConstant:40].active = YES;
    self.receipts = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    self.receipts.target = self; self.receipts.action = @selector(selectReceipt:);
    [self.receipts.widthAnchor constraintEqualToConstant:480].active = YES;
    self.undo = [self button:@"恢复原位置" action:@selector(undoReceipt:)];
    [stack addArrangedSubview:[self row:@[self.receipts,self.undo]]];
    self.receiptText = [self label:@"尚无操作记录。" size:12 weight:NSFontWeightRegular];
    [stack addArrangedSubview:self.receiptText];
    }
    self.notice = [self label:@"" size:12 weight:NSFontWeightMedium];
    self.notice.textColor = NSColor.secondaryLabelColor;
    [stack addArrangedSubview:self.notice];
    [self.notice.heightAnchor constraintGreaterThanOrEqualToConstant:32].active = YES;
    NSMutableArray *wideViews = [NSMutableArray arrayWithArray:@[intro,self.summary,self.notice]];
    if (!self.readOnly) [wideViews addObjectsFromArray:@[self.previewText,self.receiptText]];
    for (NSView *view in wideViews)
        [view.widthAnchor constraintEqualToAnchor:stack.widthAnchor].active = YES;
    [self refresh];
    [self.window center]; [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}
- (NSDictionary *)perform:(NSString *)command args:(NSDictionary *)args {
    NSDictionary *response = call(command,args);
    NSString *error = response[@"error"];
    self.notice.stringValue = error ? message(error) : @"";
    [self refresh];
    return response[@"data"];
}
- (void)refresh {
    NSDictionary *response = call(@"status",@{});
    if (response[@"error"]) { self.notice.stringValue = message(response[@"error"]); return; }
    self.state = response[@"data"];
    NSDictionary *scan = optional(self.state[@"scan"]), *plan = optional(self.state[@"plan"]);
    NSString *scope = optional(self.state[@"scope_id"]);
    self.items = scan[@"items"] ?: @[];
    BOOL unresolved = [self.state[@"unresolved"] boolValue];
    self.scan.enabled = scope != nil; self.releaseScope.enabled = scope != nil;
    if (self.readOnly) {
        NSDictionary *report=optional(self.state[@"advice"]);
        unsigned long long bytes = 0;
        for (NSDictionary *item in self.items) bytes += [item[@"bytes"] unsignedLongLongValue];
        self.summary.stringValue = scan ? [NSString stringWithFormat:@"%@\n%@ %lu 个文件 · %@ · 跳过 %lu 项%@",
            report[@"headline"] ?: @"",[scan[@"complete"] boolValue] ? @"Downloads ·" : @"部分结果 ·", self.items.count,
            [NSByteCountFormatter stringFromByteCount:bytes countStyle:NSByteCountFormatterCountStyleFile],
            [scan[@"skipped"] count], scope ? @"" : @" · 已结束访问"]
            : (scope ? @"下载文件夹已选择，点击「分析并生成建议」。" : @"选择下载文件夹，看看哪些可以清理、哪些值得保留。");
        NSArray *groups=report[@"groups"] ?: @[];
        if (!self.adviceGroup && groups.count) {
            self.adviceGroup=@"cleanup";
            for (NSDictionary *g in groups) if ([g[@"count"] integerValue]>0) {self.adviceGroup=g[@"id"];break;}
        }
        for (NSUInteger i=0;i<self.adviceGroups.count;i++) {
            NSButton *b=self.adviceGroups[i];b.enabled=report!=nil;
            if (i<groups.count) {
                NSDictionary *g=groups[i];
                b.title=[NSString stringWithFormat:@"%@\n%@ 项 · %@",g[@"label"],g[@"count"],[NSByteCountFormatter stringFromByteCount:[g[@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile]];
                b.accessibilityLabel=b.title;b.state=[g[@"id"] isEqual:self.adviceGroup] ? NSControlStateValueOn : NSControlStateValueOff;
                b.contentTintColor=b.state==NSControlStateValueOn ? NSColor.systemBlueColor : NSColor.labelColor;
            }
        }
        NSString *selectedCategory=self.categoryFilter.selectedItem.representedObject ?: @"all";
        [self.categoryFilter removeAllItems];[self.categoryFilter addItemWithTitle:@"全部类型"];self.categoryFilter.lastItem.representedObject=@"all";
        for (NSDictionary *category in report[@"categories"]) {
            [self.categoryFilter addItemWithTitle:[NSString stringWithFormat:@"%@ · %@ 项 · %@",category[@"label"],category[@"count"],[NSByteCountFormatter stringFromByteCount:[category[@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile]]];
            self.categoryFilter.lastItem.representedObject=category[@"id"];
            if ([category[@"id"] isEqual:selectedCategory]) [self.categoryFilter selectItem:self.categoryFilter.lastItem];
        }
        self.categoryFilter.enabled=report!=nil;
        NSMutableArray *visible=[NSMutableArray array];NSUInteger considered=0;
        for (NSDictionary *item in report[@"items"]) {
            if ([item[@"decision"] isEqual:@"consider"]) considered++;
            if ([item[@"group"] isEqual:self.adviceGroup] && ([selectedCategory isEqual:@"all"] || [item[@"category"] isEqual:selectedCategory])) [visible addObject:item];
        }
        self.items=visible;
        self.review.title=[NSString stringWithFormat:@"查看清理预览（%lu）",considered];self.review.accessibilityLabel=self.review.title;self.review.enabled=considered>0;
        [self.table reloadData];
        NSInteger row=-1;
        for (NSUInteger i=0;i<self.items.count;i++) if ([self.items[i][@"id"] isEqual:self.selectedID]) {row=i;break;}
        if (row<0 && self.items.count) row=0;
        if (row>=0) [self.table selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:NO];
        else [self.table deselectAll:nil];
        [self showAdvice];
        return;
    }
    self.preview.enabled = self.selectedID != nil && scope != nil && !unresolved;
    self.confirm.enabled = plan != nil && !unresolved; self.cancel.enabled = plan != nil;
    self.summary.stringValue = scan ? [NSString stringWithFormat:@"已查看 %lu 项 · 跳过 %lu 项 · 已选 %d 项",self.items.count,[scan[@"skipped"] count],self.selectedID ? 1 : 0]
        : (scope ? @"样本文件夹已选择，可以开始只读扫描。" : @"请选择本次验证的样本文件夹。");
    self.previewText.stringValue = plan ? [NSString stringWithFormat:@"预览：%@ · %@\n1 项，从样本文件夹移到系统废纸篓。确认后才会执行，原位置冲突时不会覆盖。",plan[@"item"][@"name"],[NSByteCountFormatter stringFromByteCount:[plan[@"item"][@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile]]
        : @"默认不选任何文件。勾选一项后，可以先查看操作预览。";
    [self.table reloadData];
    [self.receipts removeAllItems];
    for (NSDictionary *receipt in self.state[@"receipts"]) {
        NSString *status = [receipt[@"restore_status"] isEqual:@"restored"] ? @"已恢复" : ([receipt[@"status"] isEqual:@"trashed"] ? @"已移入废纸篓" : @"待核实／未完成");
        [self.receipts addItemWithTitle:[NSString stringWithFormat:@"%@ · %@ · %@",receipt[@"plan"][@"item"][@"name"],status,[receipt[@"id"] substringToIndex:8]]];
        self.receipts.lastItem.representedObject = receipt;
        if ([receipt[@"id"] isEqual:self.receiptID]) [self.receipts selectItem:self.receipts.lastItem];
    }
    if (!self.receipts.numberOfItems) { [self.receipts addItemWithTitle:@"尚无操作记录"]; self.receipts.enabled = NO; }
    else self.receipts.enabled = YES;
    [self selectReceipt:nil];
    if (unresolved) self.notice.stringValue = message(@"RECONCILIATION_REQUIRED");
}
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView { return self.items.count; }
- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)column row:(NSInteger)row {
    NSDictionary *item = self.items[row];
    if ([column.identifier isEqual:@"pick"]) {
        NSButton *check = [NSButton checkboxWithTitle:@"" target:self action:@selector(toggleItem:)];
        check.tag = row; check.enabled = ![item[@"protected"] boolValue];
        check.state = [self.selectedID isEqual:item[@"id"]] ? NSControlStateValueOn : NSControlStateValueOff;
        check.accessibilityLabel = [@"选择 " stringByAppendingString:item[@"name"]];
        return check;
    }
    if ([column.identifier isEqual:@"bytes"]) {
        NSTextField *size = [self label:[NSByteCountFormatter stringFromByteCount:[item[@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile] size:12 weight:NSFontWeightRegular];
        size.alignment = NSTextAlignmentRight; return size;
    }
    NSTextField *name = [self label:self.readOnly ? item[@"relative"] : item[@"name"] size:13 weight:NSFontWeightMedium];
    NSString *detail = self.readOnly ? [NSString stringWithFormat:@"%@ · %@%@",item[@"purpose"],item[@"title"],[item[@"decision"] isEqual:@"keep"] ? @" · 已记为保留" : ([item[@"decision"] isEqual:@"consider"] ? @" · 已加入预览" : @"")] : item[@"reason"];
    NSTextField *reason = [self label:detail size:11 weight:NSFontWeightRegular];
    reason.textColor = NSColor.secondaryLabelColor;
    NSStackView *cell = [NSStackView stackViewWithViews:@[name,reason]];
    cell.orientation = NSUserInterfaceLayoutOrientationVertical; cell.alignment = NSLayoutAttributeLeading; cell.spacing = 2;
    return cell;
}
- (void)showAdvice {
    NSInteger row=self.table.selectedRow;
    NSDictionary *item=(row>=0 && (NSUInteger)row<self.items.count) ? self.items[row] : nil;
    self.selectedID=item[@"id"];
    self.consider.enabled=item && [item[@"can_consider_cleanup"] boolValue] && ![item[@"decision"] isEqual:@"consider"];
    self.keep.enabled=item && ![item[@"decision"] isEqual:@"keep"];
    self.resetDecision.enabled=item && ![item[@"decision"] isEqual:@"none"];
    if (!item) {
        self.adviceDetail.string=optional(self.state[@"advice"]) ? @"当前分类下没有文件，可以切换建议组或文件分类。" : @"每条建议都会说明：文件是什么、为什么这样建议、还需确认什么，以及下一步怎么做。";
        return;
    }
    NSString *date=[self.dates stringFromDate:[NSDate dateWithTimeIntervalSince1970:[item[@"modified_at"] doubleValue]]];
    self.adviceDetail.string=[NSString stringWithFormat:@"%@｜%@\n%@\n依据：%@；修改于 %@\n建议：%@\n需确认：%@\n位置：%@ · 判断把握：%@",item[@"title"],item[@"purpose"],item[@"explanation"],
        [item[@"evidence"] componentsJoinedByString:@"；"],date,item[@"next_step"],item[@"caution"],item[@"relative"],item[@"confidence"]];
    [self.adviceDetail scrollRangeToVisible:NSMakeRange(0,0)];
}
- (void)tableViewSelectionDidChange:(NSNotification *)notification { if (self.readOnly) [self showAdvice]; }
- (void)selectAdviceGroup:(NSButton *)sender {
    self.adviceGroup=self.state[@"advice"][@"groups"][sender.tag][@"id"];
    self.selectedID=nil;
    [self refresh];
}
- (void)filterAdvice:(id)sender { self.selectedID=nil;[self refresh]; }
- (void)recordDecision:(NSString *)decision {
    if (!self.selectedID) return;
    if ([self perform:@"decide" args:@{@"item_id":self.selectedID,@"decision":decision}])
        self.notice.stringValue=@"只记录本轮选择，文件没有移动或删除。退出后不保留这些选择。";
}
- (void)considerAdvice:(id)sender { [self recordDecision:@"consider"]; }
- (void)keepAdvice:(id)sender { [self recordDecision:@"keep"]; }
- (void)resetAdvice:(id)sender { [self recordDecision:@"none"]; }
- (void)reviewAdvice:(id)sender {
    NSDictionary *review=[self perform:@"review" args:@{}];
    if (!review) return;
    NSAlert *alert=[[NSAlert alloc] init];
    alert.messageText=@"清理预览 · 不执行";
    alert.informativeText=[NSString stringWithFormat:@"已选 %@ 项 · %@\n这里展示你的选择与需要确认的条件，不代表已验证可释放空间。本次不会移动或删除文件。",review[@"count"],[NSByteCountFormatter stringFromByteCount:[review[@"bytes"] longLongValue] countStyle:NSByteCountFormatterCountStyleFile]];
    NSMutableArray *lines=[NSMutableArray array];
    for (NSDictionary *item in review[@"items"]) [lines addObject:[NSString stringWithFormat:@"%@\n%@\n%@\n需确认：%@",item[@"relative"],item[@"title"],item[@"next_step"],item[@"caution"]]];
    NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(0,0,640,240)];
    scroll.hasVerticalScroller=YES;scroll.borderType=NSBezelBorder;
    NSTextView *text=[[NSTextView alloc] initWithFrame:NSMakeRect(0,0,620,240)];
    text.editable=NO;text.font=[NSFont systemFontOfSize:13];text.textContainerInset=NSMakeSize(8,8);
    text.autoresizingMask=NSViewWidthSizable;text.textContainer.widthTracksTextView=YES;
    text.string=[lines componentsJoinedByString:@"\n\n"];
    scroll.documentView=text;alert.accessoryView=scroll;
    [alert addButtonWithTitle:@"返回建议"];
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}
- (void)toggleItem:(NSButton *)sender {
    NSDictionary *item = self.items[sender.tag];
    self.selectedID = sender.state == NSControlStateValueOn ? item[@"id"] : nil;
    [self perform:@"cancel" args:@{}];
}
- (void)chooseFolder:(id)sender { self.selectedID = nil; [self perform:@"choose" args:@{}]; }
- (void)scanFolder:(id)sender {
    self.selectedID = nil;
    if ([self perform:@"scan" args:@{@"scope_id":self.state[@"scope_id"]}] && self.readOnly)
        self.notice.stringValue=@"依据名称、版本与日期生成建议；副本内容和安装状态还需确认，候选体积不等于可释放空间。";
}
- (void)closeScope:(id)sender {
    self.selectedID = nil;
    NSDictionary *result = [self perform:@"close" args:@{}];
    if (self.readOnly && result) {
        id verification = optional(result[@"verification"]);
        NSDictionary *check = verification[@"Ok"];
        if (check && optional(check) && [check[@"changed"] intValue] == 0 && [check[@"missing"] intValue] == 0 && [check[@"added"] intValue] == 0)
            self.notice.stringValue = @"已结束目录访问；已扫描文件的路径与元数据未变化。";
        else self.notice.stringValue = @"已结束目录访问。文件核对结果保存在本机测试记录中。";
    }
}
- (void)previewItem:(id)sender { [self perform:@"preview" args:@{@"scope_id":self.state[@"scope_id"],@"item_id":self.selectedID}]; }
- (void)cancelPreview:(id)sender { self.selectedID = nil; [self perform:@"cancel" args:@{}]; }
- (void)confirmPlan:(id)sender {
    NSDictionary *plan = optional(self.state[@"plan"]);
    if (!plan) return;
    self.selectedID = nil;
    NSDictionary *receipt = [self perform:@"confirm" args:@{@"plan_id":plan[@"id"],@"version":plan[@"version"],@"confirm":@YES}];
    if (receipt) { self.receiptID = receipt[@"id"]; [self refresh]; }
}
- (void)selectReceipt:(id)sender {
    NSDictionary *r = self.receipts.selectedItem.representedObject;
    self.receiptID = r[@"id"];
    self.undo.enabled = r && optional(self.state[@"scope_id"]) && [r[@"status"] isEqual:@"trashed"] && ![r[@"restore_status"] isEqual:@"restored"] && ![self.state[@"unresolved"] boolValue];
    if (!r) self.receiptText.stringValue = @"尚无操作记录。";
    else if (optional(r[@"error"])) self.receiptText.stringValue = message(r[@"error"]);
    else if ([r[@"restore_status"] isEqual:@"restored"]) self.receiptText.stringValue = @"已恢复到原位置，操作记录已保存。";
    else if ([r[@"status"] isEqual:@"trashed"]) self.receiptText.stringValue = @"已移入系统废纸篓，操作记录已保存。恢复前会再次核对文件。";
    else self.receiptText.stringValue = @"操作尚未确认完成，请保留记录并核实文件位置。";
}
- (void)undoReceipt:(id)sender { [self perform:@"undo" args:@{@"receipt_id":self.receiptID,@"scope_id":self.state[@"scope_id"]}]; }
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender { return YES; }
- (void)applicationWillTerminate:(NSNotification *)notification { call(@"quit",@{}); }
@end

char *sp_bundle_paths(void) {
    @autoreleasepool {
        NSURL *support = [[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
        NSDictionary *paths = @{@"resources":NSBundle.mainBundle.resourcePath ?: @"",@"data":[support.path stringByAppendingPathComponent:@"SpacePerspectiveNative"]};
        NSData *data = [NSJSONSerialization dataWithJSONObject:paths options:0 error:nil];
        return strdup([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
    }
}
void sp_run(void) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        NSApp.activationPolicy = NSApplicationActivationPolicyRegular;
        SPWindow *delegate = [[SPWindow alloc] init]; NSApp.delegate = delegate;
        NSMenu *menu = [[NSMenu alloc] init];
        NSMenuItem *appItem = [[NSMenuItem alloc] init]; [menu addItem:appItem];
        NSMenu *appMenu = [[NSMenu alloc] init];
        [appMenu addItemWithTitle:@"退出空间透视" action:@selector(terminate:) keyEquivalent:@"q"];
        appItem.submenu = appMenu; NSApp.mainMenu = menu;
        [NSApp run];
    }
}
