import re
from django.core.exceptions import ValidationError


def alphaCharacterValidations(value):
    if re.search("[^\u0621-\u064Aa-zA-Z ]+",f"{value}".strip()):
        raise ValidationError(
            f"string of '{value}' is not valid ,must only characters.")


def sepcialCharsValidation(value):
    if re.search("(#|<\w*>|<\\\w*>|\$|\&|\!|\*|\(|\)|\?|\[|\])+", value):
        raise ValidationError(
            f"string of '{value}' is not valid , string must not contains  #,%,[],(),*,$,!,<>..")


allowedExtensipons = ['jpg', 'png', 'jpeg', 'gif']
extessionErrorMessage = "allowed format is :  'jpg', 'png', 'jpeg',  'gif' "


def fileSize(value):
    limit = 10 * 1024 * 1000
    if value.size > limit:
        raise ValidationError('File too large. Size should not exceed 10 MiB.')
