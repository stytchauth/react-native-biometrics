//
//  ReactNativeBiometrics.m
//
//  Created by Brandon Hines on 4/3/18.
//

#import "ReactNativeBiometrics.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <React/RCTConvert.h>

@implementation ReactNativeBiometrics

RCT_EXPORT_MODULE(ReactNativeBiometrics);

RCT_EXPORT_METHOD(isSensorAvailable: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  LAContext *context = [[LAContext alloc] init];
  NSError *la_error = nil;
  BOOL allowDeviceCredentials = [RCTConvert BOOL:params[@"allowDeviceCredentials"]];
  LAPolicy laPolicy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

  if (allowDeviceCredentials == TRUE) {
    laPolicy = LAPolicyDeviceOwnerAuthentication;
  }

  BOOL canEvaluatePolicy = [context canEvaluatePolicy:laPolicy error:&la_error];

  if (canEvaluatePolicy) {
    NSString *biometryType = [self getBiometryType:context];
    NSDictionary *result = @{
      @"available": @(YES),
      @"biometryType": biometryType
    };

    resolve(result);
  } else {
    NSString *errorMessage = [NSString stringWithFormat:@"%@", la_error];
    NSDictionary *result = @{
      @"available": @(NO),
      @"error": errorMessage
    };

    resolve(result);
  }
}

RCT_EXPORT_METHOD(createKeys: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    CFErrorRef error = NULL;
    BOOL allowDeviceCredentials = [RCTConvert BOOL:params[@"allowDeviceCredentials"]];

    SecAccessControlCreateFlags secCreateFlag = kSecAccessControlBiometryAny;

    if (allowDeviceCredentials == TRUE) {
      secCreateFlag = kSecAccessControlUserPresence;
    }

    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    secCreateFlag, &error);
    if (sacObject == NULL || error != NULL) {
      NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
      reject(@"storage_error", errorString, nil);
      return;
    }

    Keys* keys = [Curve25519 generateKeypair];

    NSData *biometricKeyService = [self getBiometricKeyService];
    NSDictionary *keyAttributes = @{
                                    (id)kSecClass: (id)kSecClassGenericPassword,
                                    (id)kSecAttrService: biometricKeyService,
                                    (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                    (id)kSecValueData: (id)keys.privateKey
                                    };

    [self deleteBiometricKey];

    NSError *storage_error = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)keyAttributes, (void *)&storage_error);

    if(keys.publicKey != nil) {
      NSString *publicKeyString = [keys.publicKey base64EncodedStringWithOptions:0];

      NSDictionary *result = @{
        @"publicKey": publicKeyString,
      };
      resolve(result);
    } else {
      NSString *message = [NSString stringWithFormat:@"Key storage error: %@", storage_error];
      reject(@"storage_error", message, nil);
    }
  });
}

RCT_EXPORT_METHOD(deleteKeys: (RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    BOOL biometricKeyExists = [self doesBiometricKeyExist];

    if (biometricKeyExists) {
      OSStatus status = [self deleteBiometricKey];

      if (status == noErr) {
        NSDictionary *result = @{
          @"keysDeleted": @(YES),
        };
        resolve(result);
      } else {
        NSString *message = [NSString stringWithFormat:@"Key not found: %@",[self keychainErrorToString:status]];
        reject(@"deletion_error", message, nil);
      }
    } else {
        NSDictionary *result = @{
          @"keysDeleted": @(NO),
        };
        resolve(result);
    }
  });
}

RCT_EXPORT_METHOD(createSignature: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSString *promptMessage = [RCTConvert NSString:params[@"promptMessage"]];
    NSString *payload = [RCTConvert NSString:params[@"payload"]];

    LAContext *context = [[LAContext alloc] init];
    context.localizedReason = promptMessage;

    NSData *biometricKeyService = [self getBiometricKeyService];
    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrService: biometricKeyService,
                            (id)kSecReturnData: @YES,
                            (id)kSecUseAuthenticationContext: context,
                            };
    NSData *privateKey;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFDataRef *)&privateKey);

    if (status == errSecSuccess) {
      NSError *error;
      NSData *dataToSign = [payload dataUsingEncoding:NSUTF8StringEncoding];
      NSData *signature = [Curve25519 signatureForPayload:dataToSign privateKey:privateKey error:&error];

      if (signature != nil) {
        NSString *signatureString = [signature base64EncodedStringWithOptions:0];
        NSDictionary *result = @{
          @"success": @(YES),
          @"signature": signatureString
        };
        resolve(result);
      } else if (error.code == errSecUserCanceled) {
        NSDictionary *result = @{
          @"success": @(NO),
          @"error": @"User cancellation"
        };
        resolve(result);
      } else {
        NSString *message = [NSString stringWithFormat:@"Signature error: %@", error];
        reject(@"signature_error", message, nil);
      }
    } else {
      NSString *message = [NSString stringWithFormat:@"Key not found: %@",[self keychainErrorToString:status]];
      reject(@"storage_error", message, nil);
    }
  });
}

RCT_EXPORT_METHOD(simplePrompt: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSString *promptMessage = [RCTConvert NSString:params[@"promptMessage"]];
    NSString *fallbackPromptMessage = [RCTConvert NSString:params[@"fallbackPromptMessage"]];
    BOOL allowDeviceCredentials = [RCTConvert BOOL:params[@"allowDeviceCredentials"]];

    LAContext *context = [[LAContext alloc] init];
    LAPolicy laPolicy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

    if (allowDeviceCredentials == TRUE) {
      laPolicy = LAPolicyDeviceOwnerAuthentication;
      context.localizedFallbackTitle = fallbackPromptMessage;
    } else {
      context.localizedFallbackTitle = @"";
    }

    [context evaluatePolicy:laPolicy localizedReason:promptMessage reply:^(BOOL success, NSError *biometricError) {
      if (success) {
        NSDictionary *result = @{
          @"success": @(YES)
        };
        resolve(result);
      } else if (biometricError.code == LAErrorUserCancel) {
        NSDictionary *result = @{
          @"success": @(NO),
          @"error": @"User cancellation"
        };
        resolve(result);
      } else {
        NSString *message = [NSString stringWithFormat:@"%@", biometricError];
        reject(@"biometric_error", message, nil);
      }
    }];
  });
}

RCT_EXPORT_METHOD(biometricKeysExist: (RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
  dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    BOOL biometricKeyExists = [self doesBiometricKeyExist];

    if (biometricKeyExists) {
      NSDictionary *result = @{
        @"keysExist": @(YES)
      };
      resolve(result);
    } else {
      NSDictionary *result = @{
        @"keysExist": @(NO)
      };
      resolve(result);
    }
  });
}

- (NSString *) getBiometricKeyService {
  return @"com.rnbiometrics.biometricKey";
}

- (BOOL) doesBiometricKeyExist {
  NSString *biometricKeyService = [self getBiometricKeyService];
  LAContext *context = [[LAContext alloc] init];
  context.interactionNotAllowed = @(YES);
  NSDictionary *searchQuery = @{
                                (id)kSecClass: (id)kSecClassGenericPassword,
                                (id)kSecAttrService: biometricKeyService,
                                (id)kSecUseAuthenticationContext: context
                                };

  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
  return status == errSecSuccess || status == errSecInteractionNotAllowed;
}

-(OSStatus) deleteBiometricKey {
  NSString *biometricKeyService = [self getBiometricKeyService];
  NSDictionary *deleteQuery = @{
                                (id)kSecClass: (id)kSecClassGenericPassword,
                                (id)kSecAttrService: biometricKeyService,
                                };

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
  return status;
}

- (NSString *)getBiometryType:(LAContext *)context
{
  if (@available(iOS 11, *)) {
    return (context.biometryType == LABiometryTypeFaceID) ? @"FaceID" : @"TouchID";
  }

  return @"TouchID";
}

- (NSString *)keychainErrorToString:(OSStatus)error {
  NSString *message = [NSString stringWithFormat:@"%ld", (long)error];

  switch (error) {
    case errSecSuccess:
      message = @"success";
      break;

    case errSecDuplicateItem:
      message = @"error item already exists";
      break;

    case errSecItemNotFound :
      message = @"error item not found";
      break;

    case errSecAuthFailed:
      message = @"error item authentication failed";
      break;

    default:
      break;
  }

  return message;
}

@end
