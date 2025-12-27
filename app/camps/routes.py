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
from app.models import Camp, Event, CampEventAssociation, AssociationStatus, EventStatus, CampMember, CampMemberRole, MemberApprovalMode, User, InventoryItem


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
            max_sites=form.max_sites.data,
            max_people=form.max_people.data,
            has_communal_kitchen=form.has_communal_kitchen.data,
            has_communal_space=form.has_communal_space.data,
            has_art_exhibits=form.has_art_exhibits.data,
            has_member_activities=form.has_member_activities.data,
            has_non_member_activities=form.has_non_member_activities.data,
            custom_amenities=form.custom_amenities.data or None,
            member_approval_mode=form.member_approval_mode.data,
            creator_id=current_user.id
        )

        db.session.add(camp)
        db.session.flush()  # Get camp.id before commit

        # Auto-add creator as approved camp manager
        creator_membership = CampMember(
            camp_id=camp.id,
            user_id=current_user.id,
            status=AssociationStatus.APPROVED.value,
            role=CampMemberRole.MANAGER.value,
            requested_at=datetime.utcnow(),
            approved_at=datetime.utcnow()
        )
        db.session.add(creator_membership)
        db.session.commit()

        flash(f"Created camp '{camp.name}' successfully! You are now a camp manager.", 'success')
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

    # Get all approved events for the dropdown (if user is camp manager)
    approved_events = []
    if current_user.is_authenticated and current_user.is_camp_manager(camp_id):
        # Get approved events that this camp hasn't requested yet
        existing_associations = camp.event_associations.with_entities(
            CampEventAssociation.event_id
        ).all()
        existing_event_ids = [assoc.event_id for assoc in existing_associations]

        approved_events = Event.query.filter(
            Event.status == EventStatus.APPROVED.value,
            Event.id.notin_(existing_event_ids)
        ).order_by(Event.start_date.asc()).all()

    # Get user's membership status
    user_membership = None
    if current_user.is_authenticated:
        user_membership = camp.get_user_membership(current_user.id)

    # Get pending request count for managers
    pending_count = camp.camp_members.filter_by(status=AssociationStatus.PENDING.value).count()

    # Get shared inventory from approved camp members
    approved_member_ids = [m.user_id for m in camp.camp_members.filter_by(
        status=AssociationStatus.APPROVED.value
    ).all()]

    shared_items = InventoryItem.query.filter(
        InventoryItem.user_id.in_(approved_member_ids),
        InventoryItem.is_shared_gear == True
    ).order_by(InventoryItem.name.asc()).all() if approved_member_ids else []

    # Group shared inventory by item name
    from collections import defaultdict
    grouped_inventory = defaultdict(lambda: {'total_quantity': 0, 'owners': [], 'descriptions': []})

    for item in shared_items:
        grouped_inventory[item.name]['total_quantity'] += item.quantity
        # Build owner name with pronouns if enabled
        owner_display = item.owner.display_name
        if item.owner.show_pronouns and item.owner.pronouns:
            owner_display = f"{owner_display} ({item.owner.pronouns})"
        grouped_inventory[item.name]['owners'].append(owner_display)
        if item.description and item.description not in grouped_inventory[item.name]['descriptions']:
            grouped_inventory[item.name]['descriptions'].append(item.description)

    # Convert to list of dicts for template
    shared_inventory = [
        {
            'name': name,
            'total_quantity': data['total_quantity'],
            'owners': ', '.join(data['owners']),
            'description': '; '.join(data['descriptions']) if data['descriptions'] else None
        }
        for name, data in sorted(grouped_inventory.items())
    ]

    return render_template('camps/detail.html',
                         camp=camp,
                         approved_events=approved_events,
                         user_membership=user_membership,
                         pending_count=pending_count,
                         shared_inventory=shared_inventory,
                         AssociationStatus=AssociationStatus,
                         CampMemberRole=CampMemberRole,
                         MemberApprovalMode=MemberApprovalMode)


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
        form.max_sites.data = camp.max_sites
        form.max_people.data = camp.max_people
        form.has_communal_kitchen.data = camp.has_communal_kitchen
        form.has_communal_space.data = camp.has_communal_space
        form.has_art_exhibits.data = camp.has_art_exhibits
        form.has_member_activities.data = camp.has_member_activities
        form.has_non_member_activities.data = camp.has_non_member_activities
        form.custom_amenities.data = camp.custom_amenities
        form.member_approval_mode.data = camp.member_approval_mode

    if form.validate_on_submit():
        camp.name = form.name.data
        camp.description = form.description.data
        camp.max_sites = form.max_sites.data
        camp.max_people = form.max_people.data
        camp.has_communal_kitchen = form.has_communal_kitchen.data
        camp.has_communal_space = form.has_communal_space.data
        camp.has_art_exhibits = form.has_art_exhibits.data
        camp.has_member_activities = form.has_member_activities.data
        camp.has_non_member_activities = form.has_non_member_activities.data
        camp.custom_amenities = form.custom_amenities.data or None
        camp.member_approval_mode = form.member_approval_mode.data

        db.session.commit()

        flash(f"Updated camp '{camp.name}'.", 'success')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    return render_template('camps/edit.html', camp=camp, form=form)


@camps_bp.route('/<int:camp_id>/request-event/<int:event_id>', methods=['POST'])
@login_required
def request_event(camp_id, event_id):
    """
    Request to join an event.

    Camp managers can request their camp to join an approved event.
    Creates a CampEventAssociation with PENDING status.

    Args:
        camp_id: The ID of the camp requesting to join.
        event_id: The ID of the event to join.

    Returns:
        Redirect to camp detail with success/error message.

    Raises:
        403: If user is not a camp manager or site admin.
    """
    camp = Camp.query.get_or_404(camp_id)
    event = Event.query.get_or_404(event_id)

    # Check permission: must be camp manager or site admin
    if not current_user.is_site_admin_or_higher and not current_user.is_camp_manager(camp_id):
        flash('Only camp managers can request event associations.', 'error')
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


# ===== Camp Membership Management Routes =====


@camps_bp.route('/<int:camp_id>/request-membership', methods=['POST'])
@login_required
def request_membership(camp_id):
    """
    Request to join a camp as a member.

    Any authenticated user can request to join a camp. Creates a CampMember
    record with PENDING status and MEMBER role (default).

    Args:
        camp_id: The ID of the camp to join.

    Returns:
        Redirect to camp detail with success/error message.
    """
    camp = Camp.query.get_or_404(camp_id)

    # Check for existing membership/request
    existing = CampMember.query.filter_by(
        camp_id=camp_id,
        user_id=current_user.id
    ).first()

    if existing:
        if existing.is_approved:
            flash(f"You are already a member of '{camp.name}'.", 'info')
        elif existing.is_pending:
            flash(f"You have already requested to join '{camp.name}'. Awaiting approval.", 'info')
        else:  # rejected
            flash(f"Your previous request to join '{camp.name}' was rejected.", 'error')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    # Create pending membership request
    membership = CampMember(
        camp_id=camp_id,
        user_id=current_user.id,
        status=AssociationStatus.PENDING.value,
        role=CampMemberRole.MEMBER.value
    )

    db.session.add(membership)
    db.session.commit()

    flash(f"Requested to join camp '{camp.name}'. Awaiting approval.", 'success')
    return redirect(url_for('camps.view_camp', camp_id=camp.id))


@camps_bp.route('/<int:camp_id>/members')
@login_required
def manage_members(camp_id):
    """
    View and manage camp member requests.

    Camp managers (or all members, depending on settings) and site admins can
    view and manage member requests. Shows pending, approved, and rejected members.

    Args:
        camp_id: The ID of the camp to manage members for.

    Returns:
        Rendered template with member requests categorized by status.

    Raises:
        403: If user doesn't have permission to manage members.
    """
    camp = Camp.query.get_or_404(camp_id)

    # Check permissions
    if not current_user.is_site_admin_or_higher:
        if not current_user.can_approve_camp_members(camp_id):
            flash('You do not have permission to manage members for this camp.', 'error')
            abort(403)

    # Get members by status
    pending = camp.get_pending_requests()
    managers = camp.get_managers()
    regular_members = camp.camp_members.filter_by(
        status=AssociationStatus.APPROVED.value,
        role=CampMemberRole.MEMBER.value
    ).all()
    rejected = camp.camp_members.filter_by(status=AssociationStatus.REJECTED.value).all()

    return render_template('camps/members.html',
                         camp=camp,
                         pending=pending,
                         managers=managers,
                         regular_members=regular_members,
                         rejected=rejected,
                         CampMemberRole=CampMemberRole,
                         AssociationStatus=AssociationStatus)


@camps_bp.route('/<int:camp_id>/approve-member/<int:user_id>', methods=['POST'])
@login_required
def approve_member(camp_id, user_id):
    """
    Approve a pending member request.

    Users with approval permissions can approve pending member requests.
    Updates status to APPROVED and sets approved_at timestamp.

    Args:
        camp_id: The ID of the camp.
        user_id: The ID of the user to approve.

    Returns:
        Redirect to member management page with success/error message.

    Raises:
        403: If user doesn't have permission to approve members.
    """
    camp = Camp.query.get_or_404(camp_id)
    user = User.query.get_or_404(user_id)

    # Check permissions
    if not current_user.is_site_admin_or_higher:
        if not current_user.can_approve_camp_members(camp_id):
            flash('You do not have permission to approve members for this camp.', 'error')
            abort(403)

    # Get the membership
    membership = CampMember.query.filter_by(
        camp_id=camp_id,
        user_id=user_id
    ).first_or_404()

    # Validate status is pending
    if not membership.is_pending:
        flash('Can only approve pending requests.', 'error')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Approve the membership
    membership.status = AssociationStatus.APPROVED.value
    membership.approved_at = datetime.utcnow()
    db.session.commit()

    flash(f"Approved {user.display_name}'s membership in '{camp.name}'.", 'success')
    return redirect(url_for('camps.manage_members', camp_id=camp_id))


@camps_bp.route('/<int:camp_id>/reject-member/<int:user_id>', methods=['POST'])
@login_required
def reject_member(camp_id, user_id):
    """
    Reject a pending member request.

    Users with approval permissions can reject pending member requests.
    Updates status to REJECTED.

    Args:
        camp_id: The ID of the camp.
        user_id: The ID of the user to reject.

    Returns:
        Redirect to member management page with success/error message.

    Raises:
        403: If user doesn't have permission to reject members.
    """
    camp = Camp.query.get_or_404(camp_id)
    user = User.query.get_or_404(user_id)

    # Check permissions
    if not current_user.is_site_admin_or_higher:
        if not current_user.can_approve_camp_members(camp_id):
            flash('You do not have permission to reject members for this camp.', 'error')
            abort(403)

    # Get the membership
    membership = CampMember.query.filter_by(
        camp_id=camp_id,
        user_id=user_id
    ).first_or_404()

    # Validate status is pending
    if not membership.is_pending:
        flash('Can only reject pending requests.', 'error')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Reject the membership
    membership.status = AssociationStatus.REJECTED.value
    db.session.commit()

    flash(f"Rejected {user.display_name}'s membership request for '{camp.name}'.", 'error')
    return redirect(url_for('camps.manage_members', camp_id=camp_id))


@camps_bp.route('/<int:camp_id>/promote-member/<int:user_id>', methods=['POST'])
@login_required
def promote_member(camp_id, user_id):
    """
    Promote a regular member to camp manager.

    Camp managers and site admins can promote approved members to manager role.
    Changes role from MEMBER to MANAGER.

    Args:
        camp_id: The ID of the camp.
        user_id: The ID of the user to promote.

    Returns:
        Redirect to member management page with success/error message.

    Raises:
        403: If user is not a camp manager or site admin.
    """
    camp = Camp.query.get_or_404(camp_id)
    user = User.query.get_or_404(user_id)

    # Check permissions: must be camp manager or site admin
    if not current_user.is_site_admin_or_higher:
        if not current_user.is_camp_manager(camp_id):
            flash('Only camp managers can promote members.', 'error')
            abort(403)

    # Get the membership
    membership = CampMember.query.filter_by(
        camp_id=camp_id,
        user_id=user_id
    ).first_or_404()

    # Validate member is approved
    if not membership.is_approved:
        flash('Can only promote approved members.', 'error')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Check if already manager
    if membership.is_manager:
        flash(f"{user.display_name} is already a camp manager.", 'info')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Promote to manager
    membership.role = CampMemberRole.MANAGER.value
    db.session.commit()

    flash(f"Promoted {user.display_name} to camp manager.", 'success')
    return redirect(url_for('camps.manage_members', camp_id=camp_id))


@camps_bp.route('/association/<int:association_id>/edit-location', methods=['GET', 'POST'])
@login_required
def edit_camp_location(association_id):
    """
    Edit camp location for a specific event association.

    Camp managers can set/edit the camp's physical location for each event.

    Args:
        association_id: The ID of the CampEventAssociation

    Returns:
        On GET: Rendered form template
        On POST: Redirect to camp detail with success message

    Raises:
        403: If user is not a camp manager or site admin
    """
    association = CampEventAssociation.query.get_or_404(association_id)
    camp = association.camp

    # Check permission: must be camp manager or site admin
    if not current_user.is_site_admin_or_higher:
        if not current_user.is_camp_manager(camp.id):
            flash('Only camp managers can edit camp location.', 'error')
            abort(403)

    if request.method == 'POST':
        location = request.form.get('location', '').strip()
        association.location = location or None
        db.session.commit()

        flash(f'Camp location updated for {association.event.title}.', 'success')
        return redirect(url_for('camps.view_camp', camp_id=camp.id))

    # GET: render simple form
    return render_template('camps/edit_location.html',
                         association=association,
                         camp=camp)


@camps_bp.route('/<int:camp_id>/demote-manager/<int:user_id>', methods=['POST'])
@login_required
def demote_manager(camp_id, user_id):
    """
    Demote a camp manager to regular member.

    Camp managers and site admins can demote managers to member role.
    Changes role from MANAGER to MEMBER. Cannot demote if only one manager remains.

    Args:
        camp_id: The ID of the camp.
        user_id: The ID of the user to demote.

    Returns:
        Redirect to member management page with success/error message.

    Raises:
        403: If user is not a camp manager or site admin.
    """
    camp = Camp.query.get_or_404(camp_id)
    user = User.query.get_or_404(user_id)

    # Check permissions: must be camp manager or site admin
    if not current_user.is_site_admin_or_higher:
        if not current_user.is_camp_manager(camp_id):
            flash('Only camp managers can demote other managers.', 'error')
            abort(403)

    # Get the membership
    membership = CampMember.query.filter_by(
        camp_id=camp_id,
        user_id=user_id
    ).first_or_404()

    # Validate member is approved manager
    if not membership.is_manager:
        flash(f"{user.display_name} is not a camp manager.", 'info')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Check if this is the last manager
    manager_count = camp.camp_members.filter_by(
        status=AssociationStatus.APPROVED.value,
        role=CampMemberRole.MANAGER.value
    ).count()

    if manager_count <= 1:
        flash('Cannot demote the last camp manager. Promote another member first.', 'error')
        return redirect(url_for('camps.manage_members', camp_id=camp_id))

    # Demote to member
    membership.role = CampMemberRole.MEMBER.value
    db.session.commit()

    flash(f"Demoted {user.display_name} to regular member.", 'success')
    return redirect(url_for('camps.manage_members', camp_id=camp_id))
