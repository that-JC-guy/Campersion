"""
Event management routes.

Provides CRUD operations for events with role-based access control
and approval workflow. Event managers create events with pending status,
site admins approve/reject them, and creators can edit their own events.
"""

from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.events import events_bp
from app.events.forms import EventForm
from app import db
from app.models import Event, EventStatus, UserRole
from app.auth.decorators import require_role_or_higher


@events_bp.route('/')
def list_events():
    """
    Display list of events based on user role.

    - Site admins and global admins see all events
    - Event managers see all approved events + their own events (any status)
    - All other users (including unauthenticated) see only approved events

    Returns:
        Rendered template with event list filtered by permissions.
    """
    if current_user.is_authenticated and current_user.is_site_admin_or_higher:
        # Site admins see all events
        events = Event.query.order_by(Event.created_at.desc()).all()
    elif current_user.is_authenticated and current_user.has_role_or_higher(UserRole.EVENT_MANAGER):
        # Event managers see their own events (any status) OR all approved events
        from sqlalchemy import or_
        events = Event.query.filter(
            or_(
                Event.creator_id == current_user.id,
                Event.status == EventStatus.APPROVED.value
            )
        ).order_by(Event.created_at.desc()).all()
    else:
        # All other users (including unauthenticated) see only approved events
        events = Event.query.filter_by(status=EventStatus.APPROVED.value)\
                           .order_by(Event.start_date.asc()).all()

    return render_template('events/list.html', events=events, EventStatus=EventStatus)


@events_bp.route('/create', methods=['GET', 'POST'])
@login_required
@require_role_or_higher(UserRole.EVENT_MANAGER)
def create_event():
    """
    Create a new event.

    Accessible to event managers and above. Events are created with
    'pending' status and require site admin approval.

    Returns:
        On GET: Rendered form template.
        On POST: Redirect to event list with success message.
    """
    form = EventForm()

    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            location=form.location.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            event_manager_email=form.event_manager_email.data,
            event_manager_phone=form.event_manager_phone.data,
            safety_manager_email=form.safety_manager_email.data,
            safety_manager_phone=form.safety_manager_phone.data,
            business_manager_email=form.business_manager_email.data,
            business_manager_phone=form.business_manager_phone.data,
            board_email=form.board_email.data,
            status=EventStatus.PENDING.value,
            creator_id=current_user.id
        )

        db.session.add(event)
        db.session.commit()

        flash(f"Created event '{event.title}'. Awaiting site admin approval.", 'success')
        return redirect(url_for('events.list_events'))

    return render_template('events/create.html', form=form)


@events_bp.route('/<int:event_id>')
def view_event(event_id):
    """
    View event details.

    - Event creators can view their own events regardless of status
    - Site admins can view all events
    - All other users (including unauthenticated) can only view approved events

    Args:
        event_id: The ID of the event to view.

    Returns:
        Rendered event detail template.

    Raises:
        403: If user doesn't have permission to view this event.
    """
    event = Event.query.get_or_404(event_id)

    # Check permissions
    if current_user.is_authenticated and current_user.is_site_admin_or_higher:
        # Site admins can view all events
        pass
    elif current_user.is_authenticated and event.creator_id == current_user.id:
        # Creators can view their own events
        pass
    else:
        # All other users (including unauthenticated) can only view approved events
        if event.status != EventStatus.APPROVED.value:
            abort(403)

    return render_template('events/detail.html', event=event, EventStatus=EventStatus)


@events_bp.route('/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
@require_role_or_higher(UserRole.EVENT_MANAGER)
def edit_event(event_id):
    """
    Edit an existing event.

    Event creators can edit their own events. Site admins can edit any event.

    Args:
        event_id: The ID of the event to edit.

    Returns:
        On GET: Rendered form template with pre-populated data.
        On POST: Redirect to event detail with success message.

    Raises:
        403: If user is not the creator or a site admin.
    """
    event = Event.query.get_or_404(event_id)

    # Check permissions: must be creator or site admin
    if event.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only edit your own events.', 'error')
        abort(403)

    form = EventForm()

    # Pre-populate form on GET
    if request.method == 'GET':
        form.title.data = event.title
        form.description.data = event.description
        form.location.data = event.location
        form.start_date.data = event.start_date
        form.end_date.data = event.end_date
        form.event_manager_email.data = event.event_manager_email
        form.event_manager_phone.data = event.event_manager_phone
        form.safety_manager_email.data = event.safety_manager_email
        form.safety_manager_phone.data = event.safety_manager_phone
        form.business_manager_email.data = event.business_manager_email
        form.business_manager_phone.data = event.business_manager_phone
        form.board_email.data = event.board_email

    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        event.location = form.location.data
        event.start_date = form.start_date.data
        event.end_date = form.end_date.data
        event.event_manager_email = form.event_manager_email.data
        event.event_manager_phone = form.event_manager_phone.data
        event.safety_manager_email = form.safety_manager_email.data
        event.safety_manager_phone = form.safety_manager_phone.data
        event.business_manager_email = form.business_manager_email.data
        event.business_manager_phone = form.business_manager_phone.data
        event.board_email = form.board_email.data

        db.session.commit()

        flash(f"Updated event '{event.title}'.", 'success')
        return redirect(url_for('events.view_event', event_id=event.id))

    return render_template('events/edit.html', event=event, form=form)


@events_bp.route('/<int:event_id>/approve', methods=['POST'])
@login_required
@require_role_or_higher(UserRole.SITE_ADMIN)
def approve_event(event_id):
    """
    Approve a pending event.

    Only site admins and global admins can approve events.

    Args:
        event_id: The ID of the event to approve.

    Returns:
        Redirect to event list with success/error message.
    """
    event = Event.query.get_or_404(event_id)

    if event.status != EventStatus.PENDING.value:
        flash('Can only approve pending events.', 'error')
        return redirect(url_for('events.list_events'))

    event.status = EventStatus.APPROVED.value
    db.session.commit()

    flash(f"Approved event '{event.title}'.", 'success')
    return redirect(url_for('events.list_events'))


@events_bp.route('/<int:event_id>/reject', methods=['POST'])
@login_required
@require_role_or_higher(UserRole.SITE_ADMIN)
def reject_event(event_id):
    """
    Reject a pending event.

    Only site admins and global admins can reject events.

    Args:
        event_id: The ID of the event to reject.

    Returns:
        Redirect to event list with success/error message.
    """
    event = Event.query.get_or_404(event_id)

    if event.status != EventStatus.PENDING.value:
        flash('Can only reject pending events.', 'error')
        return redirect(url_for('events.list_events'))

    event.status = EventStatus.REJECTED.value
    db.session.commit()

    flash(f"Rejected event '{event.title}'.", 'error')
    return redirect(url_for('events.list_events'))


@events_bp.route('/<int:event_id>/cancel', methods=['POST'])
@login_required
def cancel_event(event_id):
    """
    Cancel an approved event.

    Event creators can cancel their own events. Site admins can cancel any event.
    Only approved events can be cancelled.

    Args:
        event_id: The ID of the event to cancel.

    Returns:
        Redirect to event list with success/error message.

    Raises:
        403: If user is not the creator or a site admin.
    """
    event = Event.query.get_or_404(event_id)

    # Check permissions: must be creator or site admin
    if event.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only cancel your own events.', 'error')
        abort(403)

    if event.status != EventStatus.APPROVED.value:
        flash('Can only cancel approved events.', 'error')
        return redirect(url_for('events.list_events'))

    event.status = EventStatus.CANCELLED.value
    db.session.commit()

    flash(f"Cancelled event '{event.title}'.", 'warning')
    return redirect(url_for('events.list_events'))
