"""
Forms for main application features.

This module defines WTForms for user profile management and inventory.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange, Regexp, ValidationError
from app.models import User
from flask_login import current_user


class ProfileForm(FlaskForm):
    """
    User profile editing form.

    Allows users to update their personal information including
    name, pronouns, contact details, and address.
    """

    # Name fields
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(max=100, message='First name must be less than 100 characters')
        ],
        render_kw={'placeholder': 'John'}
    )

    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(max=100, message='Last name must be less than 100 characters')
        ],
        render_kw={'placeholder': 'Doe'}
    )

    preferred_name = StringField(
        'Preferred Name/Handle',
        validators=[
            DataRequired(message='Preferred name/handle is required'),
            Length(max=100, message='Preferred name must be less than 100 characters')
        ],
        render_kw={'placeholder': 'Johnny, JDoe, etc.'}
    )

    show_full_name = BooleanField(
        'Show my full name instead of preferred name/handle',
        default=False
    )

    pronouns = StringField(
        'Pronouns (Optional)',
        validators=[
            Optional(),
            Length(max=50, message='Pronouns must be less than 50 characters')
        ],
        render_kw={'placeholder': 'she/her, he/him, they/them, etc.'}
    )

    show_pronouns = BooleanField(
        'Display my pronouns with my name',
        default=False
    )

    # Phone fields - using Optional validator with Regexp for validation
    phone_regex = r'^[\d\s\-\(\)\+\.]+$'
    phone_message = 'Please enter a valid phone number'

    home_phone = StringField(
        'Home Phone (Optional)',
        validators=[
            Optional(),
            Length(max=20),
            Regexp(phone_regex, message=phone_message)
        ],
        render_kw={'placeholder': '(555) 123-4567'}
    )

    mobile_phone = StringField(
        'Mobile Phone (Optional)',
        validators=[
            Optional(),
            Length(max=20),
            Regexp(phone_regex, message=phone_message)
        ],
        render_kw={'placeholder': '(555) 123-4567'}
    )

    work_phone = StringField(
        'Work Phone (Optional)',
        validators=[
            Optional(),
            Length(max=20),
            Regexp(phone_regex, message=phone_message)
        ],
        render_kw={'placeholder': '(555) 123-4567'}
    )

    # Address fields
    address_line1 = StringField(
        'Address Line 1 (Optional)',
        validators=[
            Optional(),
            Length(max=255, message='Address must be less than 255 characters')
        ],
        render_kw={'placeholder': '123 Main Street'}
    )

    address_line2 = StringField(
        'Address Line 2 (Optional)',
        validators=[
            Optional(),
            Length(max=255, message='Address must be less than 255 characters')
        ],
        render_kw={'placeholder': 'Apt 4B'}
    )

    city = StringField(
        'City (Optional)',
        validators=[
            Optional(),
            Length(max=100, message='City must be less than 100 characters')
        ],
        render_kw={'placeholder': 'San Francisco'}
    )

    state = StringField(
        'State/Province (Optional)',
        validators=[
            Optional(),
            Length(max=50, message='State must be less than 50 characters')
        ],
        render_kw={'placeholder': 'CA'}
    )

    zip_code = StringField(
        'ZIP/Postal Code (Optional)',
        validators=[
            Optional(),
            Length(max=20, message='ZIP code must be less than 20 characters')
        ],
        render_kw={'placeholder': '94102'}
    )

    country = SelectField(
        'Country',
        choices=[
            ('US', 'United States'),
            ('CA', 'Canada'),
            ('MX', 'Mexico'),
            ('GB', 'United Kingdom'),
            ('AU', 'Australia'),
            ('NZ', 'New Zealand'),
            ('OTHER', 'Other')
        ],
        validators=[DataRequired()],
        default='US'
    )

    submit = SubmitField('Update Profile')


class EmailChangeForm(FlaskForm):
    """
    Email change request form.

    Allows users to request changing their email address.
    A verification email will be sent to the new address.
    """

    new_email = StringField(
        'New Email Address',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address'),
            Length(max=255, message='Email must be less than 255 characters')
        ],
        render_kw={'placeholder': 'newemail@example.com'}
    )

    submit = SubmitField('Send Verification Email')

    def validate_new_email(self, field):
        """
        Validate that new email is different from current and not already in use.

        Args:
            field: The new_email field to validate

        Raises:
            ValidationError: If email is same as current or already registered
        """
        # Check if email is same as current
        if field.data.lower() == current_user.email.lower():
            raise ValidationError('This is already your current email address.')

        # Check if email is already registered to another user
        existing_user = User.query.filter_by(email=field.data.lower()).first()
        if existing_user:
            raise ValidationError('This email address is already registered to another account.')


class InventoryItemForm(FlaskForm):
    """
    Inventory item creation and editing form.

    Allows users to add or edit camping gear and equipment.
    """

    name = StringField(
        'Item Name',
        validators=[
            DataRequired(message='Item name is required'),
            Length(max=255, message='Name must be less than 255 characters')
        ],
        render_kw={'placeholder': 'e.g., 4-Person Tent, Camping Chair'}
    )

    quantity = IntegerField(
        'Quantity',
        validators=[
            DataRequired(message='Quantity is required'),
            NumberRange(min=0, message='Quantity must be 0 or greater')
        ],
        default=1,
        render_kw={'placeholder': '1'}
    )

    description = TextAreaField(
        'Description (Optional)',
        validators=[
            Optional(),
            Length(max=1000, message='Description must be less than 1000 characters')
        ],
        render_kw={'placeholder': 'Additional details about this item...', 'rows': 3}
    )

    is_shared_gear = BooleanField(
        'Share this item with other users',
        default=False
    )

    submit = SubmitField('Save Item')
