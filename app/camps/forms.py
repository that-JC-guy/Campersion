"""
Forms for camp management.

This module defines WTForms for creating and editing camps.
Any authenticated member can create camps to join events.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, BooleanField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, ValidationError


class CampForm(FlaskForm):
    """
    Form for creating and editing camps.

    Used by members to create new camps or update existing ones.
    Includes validation for required fields and capacity constraints.
    """

    name = StringField(
        'Camp Name',
        validators=[
            DataRequired(message='Camp name is required'),
            Length(max=255, message='Name must be less than 255 characters')
        ],
        render_kw={'placeholder': 'e.g., Rainbow Village, Sunset Camp'}
    )

    description = TextAreaField(
        'Description',
        validators=[
            DataRequired(message='Description is required'),
            Length(min=10, message='Description must be at least 10 characters')
        ],
        render_kw={'placeholder': 'Describe your camp...', 'rows': 5}
    )

    max_sites = IntegerField(
        'Maximum Sites',
        validators=[
            DataRequired(message='Maximum sites is required'),
            NumberRange(min=1, message='Must have at least 1 site')
        ],
        render_kw={'placeholder': 'e.g., 20'}
    )

    max_people = IntegerField(
        'Maximum People',
        validators=[
            DataRequired(message='Maximum people is required'),
            NumberRange(min=1, message='Must accommodate at least 1 person')
        ],
        render_kw={'placeholder': 'e.g., 100'}
    )

    # Amenities
    has_communal_kitchen = BooleanField('Communal Kitchen')
    has_communal_space = BooleanField('Communal Space')
    has_art_exhibits = BooleanField('Art Exhibits')
    has_member_activities = BooleanField('Member Activities')
    has_non_member_activities = BooleanField('Non-Member Activities')
    custom_amenities = StringField(
        'Custom Amenities',
        validators=[Length(max=500, message='Custom amenities must be less than 500 characters')],
        render_kw={'placeholder': 'e.g., Hot Showers, WiFi, Bike Parking (comma separated)'}
    )

    # Member approval mode
    member_approval_mode = SelectField(
        'Member Approval Mode',
        choices=[
            ('manager_only', 'Manager Only - Only camp managers can approve new members'),
            ('all_members', 'All Members - Any approved member can approve new members')
        ],
        default='manager_only',
        validators=[DataRequired()],
        render_kw={
            'class': 'form-select',
            'aria-describedby': 'memberApprovalModeHelp'
        }
    )

    submit = SubmitField('Save Camp')

    def validate_max_people(self, field):
        """
        Validate that max_people is reasonable compared to max_sites.

        Args:
            field: The max_people field to validate

        Raises:
            ValidationError: If max_people is less than max_sites
        """
        if self.max_sites.data and field.data:
            if field.data < self.max_sites.data:
                raise ValidationError('Maximum people should be at least equal to maximum sites.')
