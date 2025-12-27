"""
Forms for event management.

This module defines WTForms for creating and editing events.
Event managers use these forms to submit event proposals for site admin approval.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError, Email, Optional
from datetime import date


class EventForm(FlaskForm):
    """
    Form for creating and editing events.

    Used by event managers to create new events or update existing ones.
    Includes validation for date logic (end >= start, start >= today).
    """

    title = StringField(
        'Event Title',
        validators=[
            DataRequired(message='Event title is required'),
            Length(max=255, message='Title must be less than 255 characters')
        ],
        render_kw={'placeholder': 'e.g., Summer Music Festival 2024'}
    )

    description = TextAreaField(
        'Description',
        validators=[
            DataRequired(message='Description is required'),
            Length(min=10, message='Description must be at least 10 characters')
        ],
        render_kw={'placeholder': 'Describe your event...', 'rows': 5}
    )

    location = StringField(
        'Location',
        validators=[
            DataRequired(message='Location is required'),
            Length(max=255, message='Location must be less than 255 characters')
        ],
        render_kw={'placeholder': 'e.g., Central Park, New York'}
    )

    start_date = DateField(
        'Start Date',
        validators=[DataRequired(message='Start date is required')],
        format='%Y-%m-%d'
    )

    end_date = DateField(
        'End Date',
        validators=[DataRequired(message='End date is required')],
        format='%Y-%m-%d'
    )

    # Contact information
    event_manager_email = StringField(
        'Event Manager Email',
        validators=[Optional(), Email(message='Invalid email address')],
        render_kw={'placeholder': 'e.g., manager@example.com'}
    )

    event_manager_phone = StringField(
        'Event Manager Phone',
        validators=[Optional(), Length(max=20, message='Phone number must be less than 20 characters')],
        render_kw={'placeholder': 'e.g., (555) 123-4567'}
    )

    safety_manager_email = StringField(
        'Safety Manager Email',
        validators=[Optional(), Email(message='Invalid email address')],
        render_kw={'placeholder': 'e.g., safety@example.com'}
    )

    safety_manager_phone = StringField(
        'Safety Manager Phone',
        validators=[Optional(), Length(max=20, message='Phone number must be less than 20 characters')],
        render_kw={'placeholder': 'e.g., (555) 123-4567'}
    )

    business_manager_email = StringField(
        'Business Manager Email',
        validators=[Optional(), Email(message='Invalid email address')],
        render_kw={'placeholder': 'e.g., business@example.com'}
    )

    business_manager_phone = StringField(
        'Business Manager Phone',
        validators=[Optional(), Length(max=20, message='Phone number must be less than 20 characters')],
        render_kw={'placeholder': 'e.g., (555) 123-4567'}
    )

    board_email = StringField(
        'Board of Directors Email',
        validators=[Optional(), Email(message='Invalid email address')],
        render_kw={'placeholder': 'e.g., board@example.com'}
    )

    submit = SubmitField('Save Event')

    def validate_end_date(self, field):
        """
        Validate that end date is not before start date.

        Args:
            field: The end_date field to validate

        Raises:
            ValidationError: If end date is before start date
        """
        if self.start_date.data and field.data:
            if field.data < self.start_date.data:
                raise ValidationError('End date cannot be before start date.')

    def validate_start_date(self, field):
        """
        Validate that start date is not in the past.

        Args:
            field: The start_date field to validate

        Raises:
            ValidationError: If start date is in the past
        """
        if field.data and field.data < date.today():
            raise ValidationError('Start date cannot be in the past.')
