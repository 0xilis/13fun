//
//  ViewController.m
//  0pwn
//
//  Created by Zachary Keffaber on 7/11/22.
//

#import "ViewController.h"
#include "0pwn.h"

@interface ViewController ()
@property (strong, nonatomic) IBOutlet UIView *mainView;
@property (weak, nonatomic) IBOutlet UIButton *jbButton;
@property (weak, nonatomic) IBOutlet UIImageView *heart;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    _mainView.layer.cornerRadius = 10.0;
    _jbButton.layer.cornerRadius = 5.0;
    //_heart.alpha = 0.5;
    // Do any additional setup after loading the view.
}

- (IBAction)jbButtonPressed:(id)sender {
    NSLog(@"lez start da mayhem\n");
    openpwnage64();
}

@end
