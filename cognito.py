import boto3
import hmac
import hashlib
import base64


class CognitoManager:
    USER_POOL_ID = ''
    CLIENT_ID = ''
    CLIENT_SECRET = ''
    REGION = ''

    def __init__(self):
        pass

    @staticmethod
    def get_secret_hash(username):
        msg = username + CognitoManager.CLIENT_ID
        dig = hmac.new(
            str(CognitoManager.CLIENT_SECRET).encode('utf-8'),
            msg=str(msg).encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()

    @staticmethod
    def sign_up_user(email, password, role, cop_id):
        client = boto3.client('cognito-idp', region_name=CognitoManager.REGION)
        username = email  # Assuming username is the same as the email

        try:
            response = client.sign_up(
                ClientId=CognitoManager.CLIENT_ID,
                SecretHash=CognitoManager.get_secret_hash(username),
                Username=username,
                Password=password,
                UserAttributes=[
                    {
                        'Name': "email",
                        'Value': email
                    },
                    {
                        'Name': "custom:role",
                        'Value': role
                    },
                    {
                        'Name': "custom:cop_id",
                        'Value': cop_id
                    }
                ],
                ValidationData=[
                    {
                        'Name': "email",
                        'Value': email
                    },
                    {
                        'Name': "custom:role",
                        'Value': role
                    },
                    {
                        'Name': "custom:cop_id",
                        'Value': cop_id
                    }
                ]
            )

        except client.exceptions.UsernameExistsException as e:
            return {
                "error": False,
                "success": True,
                "message": "This username already exists",
                "data": None
            }
        except client.exceptions.InvalidPasswordException as e:
            return {
                "error": False,
                "success": True,
                "message": "Password should have Caps, Special chars, Numbers",
                "data": None
            }
        except client.exceptions.UserLambdaValidationException as e:
            return {
                "error": False,
                "success": True,
                "message": "Email already exists",
                "data": None
            }
        except Exception as e:
            return {
                "error": False,
                "success": True,
                "message": str(e),
                "data": None
            }

        return {
            "error": False,
            "success": True,
            "message": "Please confirm your signup, check Email for validation code",
            "UserSub": response['UserSub']
        }

    @staticmethod
    def confirm_sign_up(username, code):
        client = boto3.client('cognito-idp', region_name=CognitoManager.REGION)

        try:
            response = client.confirm_sign_up(
                ClientId=CognitoManager.CLIENT_ID,
                SecretHash=CognitoManager.get_secret_hash(username),
                Username=username,
                ConfirmationCode=code,
                ForceAliasCreation=False,
            )
        except client.exceptions.UserNotFoundException:
            return {"error": True, "success": False, "message": "Username doesn't exist"}
        except client.exceptions.CodeMismatchException:
            return {"error": True, "success": False, "message": "Invalid Verification code"}
        except client.exceptions.NotAuthorizedException:
            return {"error": True, "success": False, "message": "User is already confirmed"}
        except Exception as e:
            return {"error": True, "success": False, "message": f"Unknown error {e}"}

        return {
            "error": False,
            "success": True,
            "message": "User confirmed successfully",
            "Response": response
        }

    @staticmethod
    def resend_verification_code(username):
        client = boto3.client('cognito-idp', region_name=CognitoManager.REGION)
        try:
            response = client.resend_confirmation_code(
                ClientId=CognitoManager.CLIENT_ID,
                SecretHash=CognitoManager.get_secret_hash(username),
                Username=username,
            )
        except client.exceptions.UserNotFoundException:
            return {"error": True, "success": False, "message": "Username doesn't exist"}
        except client.exceptions.InvalidParameterException:
            return {"error": True, "success": False, "message": "User is already confirmed"}
        except Exception as e:
            return {"error": True, "success": False, "message": f"Unknown error {e}"}

        return {
            "error": False,
            "success": True,
            "message": "Verification code resent successfully"
        }


if __name__ == "__main__":
    cognito_manager = CognitoManager()

    # result = CognitoManager.sign_up_user("dinirangapremanayake@gmail.com", "Dashitha@1234", "officer", "COP001")
    # print(result)

    # result = CognitoManager.confirm_sign_up("dinirangapremanayake@gmail.com", "987635")
    # print(result)

    # result = CognitoManager.resend_verification_code("dinirangapremanayake@gmail.com")
    # print(result)