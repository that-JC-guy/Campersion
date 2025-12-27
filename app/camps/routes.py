"""
Camp management routes.

Provides CRUD operations for camps and camp-event association approval workflow.
Any authenticated member can create camps. Event creators approve camp requests.
"""

from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from datetime import datetime
from app.camps import camps_bp
from app.camps.forms import CampForm
from app import db
from app.models import Camp, Event, CampEventAssociation, AssociationStatus, EventStatus


@camps_bp.route('/')
def list_camps():
    """
    Display list of all camps.

    All users (including unauthenticated) can view the camp list.
    Shows camp name, location, capacity, and creator information.

    Returns:
        Rendered template with list of all camps.
    """
    camps = Camp.query.order_by(Camp.created_at.desc()).all()
    return render_template('camps/list.html', camps=camps)


@camps_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_camp():
    """
    Create a new camp.

    Accessible to any authenticated member. Camps are created immediately
    (no approval workflow) and can then request to join events.

    Returns:
        On GET: Rendered form template.
        On POST: Redirect to camp detail with success message.
    """
    form = CampForm()

    if form.validate_on_submit():
        camp = Camp(
            name=form.name.data,
            description=form.description.data,
            location=form.location.data,
            max_sites=form.max_sites.data,
            max_people=form.max_people.data,
            has_communal_kitchen=form.has_communal_kitchen.data,
            has_communal_space=form.has_communal_space.data,
            has_art_exhibits=form.has_art_exhibits.data,
            has_member_activities=form.has_member_activities.data,
            has_non_member_activities=form.has_non_member_activities.data,
            creator_id=current_user.id
        )

        db.session.add(camp)
        db.session.commit()

        flash(f"Created camp '{camp.name}' successfully!", 'success')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    return render_template('camps/create.html', form=form)


@camps_bp.route('/<int:camp_id>')
def view_camp(camp_id):
    """
    View camp details.

    All users (including unauthenticated) can view camp details.
    Shows full camp information, amenities, and associated events.

    Args:
        camp_id: The ID of the camp to view.

    Returns:
        Rendered camp detail template.
    """
    camp = Camp.query.get_or_404(camp_id)

    # Get all approved events for the dropdown (if user is camp creator)
    approved_events = []
    if current_user.is_authenticated and camp.creator_id == current_user.id:
        # Get approved events that this camp hasn't requested yet
        existing_associations = camp.event_associations.with_entities(
            CampEventAssociation.event_id
        ).all()
        existing_event_ids = [assoc.event_id for assoc in existing_associations]

        approved_events = Event.query.filter(
            Event.status == EventStatus.APPROVED.value,
            Event.id.notin_(existing_event_ids)
        ).order_by(Event.start_date.asc()).all()

    return render_template('camps/detail.html', camp=camp,
                         approved_events=approved_events,
                         AssociationStatus=AssociationStatus)


@camps_bp.route('/<int:camp_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_camp(camp_id):
    """
    Edit an existing camp.

    Camp creators can edit their own camps. Site admins can edit any camp.

    Args:
        camp_id: The ID of the camp to edit.

    Returns:
        On GET: Rendered form template with pre-populated data.
        On POST: Redirect to camp detail with success message.

    Raises:
        403: If user is not the creator or a site admin.
    """
    camp = Camp.query.get_or_404(camp_id)

    # Check permissions: must be creator or site admin
    if camp.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only edit your own camps.', 'error')
        abort(403)

    form = CampForm()

    # Pre-populate form on GET
    if request.method == 'GET':
        form.name.data = camp.name
        form.description.data = camp.description
        form.location.data = camp.location
        form.max_sites.data = camp.max_sites
        form.max_people.data = camp.max_people
        form.has_communal_kitchen.data = camp.has_communal_kitchen
        form.has_communal_space.data = camp.has_communal_space
        form.has_art_exhibits.data = camp.has_art_exhibits
        form.has_member_activities.data = camp.has_member_activities
        form.has_non_member_activities.data = camp.has_non_member_activities

    if form.validate_on_submit():
        camp.name = form.name.data
        camp.description = form.description.data
        camp.location = form.location.data
        camp.max_sites = form.max_sites.data
        camp.max_people = form.max_people.data
        camp.has_communal_kitchen = form.has_communal_kitchen.data
        camp.has_communal_space = form.has_communal_space.data
        camp.has_art_exhibits = form.has_art_exhibits.data
        camp.has_member_activities = form.has_member_activities.data
        camp.has_non_member_activities = form.has_non_member_activities.data

        db.session.commit()

        flash(f"Updated camp '{camp.name}'.", 'success')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    return render_template('camps/edit.html', camp=camp, form=form)


@camps_bp.route('/<int:camp_id>/request-event/<int:event_id>', methods=['POST'])
@login_required
def request_event(camp_id, event_id):
    """
    Request to join an event.

    Camp creator can request their camp to join an approved event.
    Creates a CampEventAssociation with PENDING status.

    Args:
        camp_id: The ID of the camp requesting to join.
        event_id: The ID of the event to join.

    Returns:
        Redirect to camp detail with success/error message.

    Raises:
        403: If user is not the camp creator.
    """
    camp = Camp.query.get_or_404(camp_id)
    event = Event.query.get_or_404(event_id)

    # Check permission: must be camp creator
    if camp.creator_id != current_user.id:
        flash('You can only manage your own camps.', 'error')
        abort(403)

    # Validate event is approved
    if event.status != EventStatus.APPROVED.value:
        flash('Can only request to join approved events.', 'error')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    # Check for existing association
    existing = CampEventAssociation.query.filter_by(
        camp_id=camp_id,
        event_id=event_id
    ).first()

    if existing:
        flash(f"Camp '{camp.name}' has already requested to join '{event.title}'.", 'error')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    # Create pending association
    association = CampEventAssociation(
        camp_id=camp_id,
        event_id=event_id,
        status=AssociationStatus.PENDING.value
    )

    db.session.add(association)
    db.session.commit()

    flash(f"Requested to join event '{event.title}'. Awaiting event creator approval.", 'success')
    return redirect(url_for('camps.view_camp', camp_id=camp.id))


@camps_bp.route('/events/<int:event_id>/camps')
@login_required
def event_camps(event_id):
    """
    View camp requests for an event.

    Event creators and site admins can view and manage camp requests for events.
    Shows pending, approved, and rejected camps.

    Args:
        event_id: The ID of the event to view camp requests for.

    Returns:
        Rendered template with camp requests categorized by status.

    Raises:
        403: If user is not the event creator or site admin.
    """
    event = Event.query.get_or_404(event_id)

    # Check permission: must be event creator or site admin
    if event.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only manage camp requests for your own events.', 'error')
        abort(403)

    # Get associations by status
    pending = event.camp_associations.filter_by(status=AssociationStatus.PENDING.value).all()
    approved = event.camp_associations.filter_by(status=AssociationStatus.APPROVED.value).all()
    rejected = event.camp_associations.filter_by(status=AssociationStatus.REJECTED.value).all()

    return render_template('events/camps.html', event=event,
                         pending=pending, approved=approved, rejected=rejected)


@camps_bp.route('/events/<int:event_id>/approve-camp/<int:camp_id>', methods=['POST'])
@login_required
def approve_camp(event_id, camp_id):
    """
    Approve a camp request for an event.

    Event creators and site admins can approve pending camp requests.
    Updates association status to APPROVED and sets approved_at timestamp.

    Args:
        event_id: The ID of the event.
        camp_id: The ID of the camp to approve.

    Returns:
        Redirect to event camps page with success/error message.

    Raises:
        403: If user is not the event creator or site admin.
    """
    event = Event.query.get_or_404(event_id)
    camp = Camp.query.get_or_404(camp_id)

    # Check permission: must be event creator or site admin
    if event.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only manage camp requests for your own events.', 'error')
        abort(403)

    # Get the association
    association = CampEventAssociation.query.filter_by(
        camp_id=camp_id,
        event_id=event_id
    ).first_or_404()

    # Validate status is pending
    if association.status != AssociationStatus.PENDING.value:
        flash('Can only approve pending requests.', 'error')
        return redirect(url_for('camps.event_camps', event_id=event_id))

    # Approve the association
    association.status = AssociationStatus.APPROVED.value
    association.approved_at = datetime.utcnow()
    db.session.commit()

    flash(f"Approved camp '{camp.name}' for event '{event.title}'.", 'success')
    return redirect(url_for('camps.event_camps', event_id=event_id))


@camps_bp.route('/events/<int:event_id>/reject-camp/<int:camp_id>', methods=['POST'])
@login_required
def reject_camp(event_id, camp_id):
    """
    Reject a camp request for an event.

    Event creators and site admins can reject pending camp requests.
    Updates association status to REJECTED.

    Args:
        event_id: The ID of the event.
        camp_id: The ID of the camp to reject.

    Returns:
        Redirect to event camps page with success/error message.

    Raises:
        403: If user is not the event creator or site admin.
    """
    event = Event.query.get_or_404(event_id)
    camp = Camp.query.get_or_404(camp_id)

    # Check permission: must be event creator or site admin
    if event.creator_id != current_user.id and not current_user.is_site_admin_or_higher:
        flash('You can only manage camp requests for your own events.', 'error')
        abort(403)

    # Get the association
    association = CampEventAssociation.query.filter_by(
        camp_id=camp_id,
        event_id=event_id
    ).first_or_404()

    # Validate status is pending
    if association.status != AssociationStatus.PENDING.value:
        flash('Can only reject pending requests.', 'error')
        return redirect(url_for('camps.event_camps', event_id=event_id))

    # Reject the association
    association.status = AssociationStatus.REJECTED.value
    db.session.commit()

    flash(f"Rejected camp '{camp.name}' for event '{event.title}'.", 'error')
    return redirect(url_for('camps.event_camps', event_id=event_id))
