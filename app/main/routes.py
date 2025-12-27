"""
Main application routes.

This module handles the primary application routes including
the home page, user dashboard, profile management, and inventory.
"""

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.main import main_bp
from app import db
from app.models import InventoryItem, User, CampMember, AssociationStatus
from app.main.forms import ProfileForm, EmailChangeForm, InventoryItemForm
from app.auth.email import send_email_change_verification


@main_bp.route('/')
def index():
    """
    Home page route.

    If user is already logged in, redirect to dashboard.
    Otherwise, redirect to login page.

    Returns:
        Redirect to dashboard or login page
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    else:
        return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard redirect.

    Dashboard has been merged with the profile page.
    This route now redirects to the profile view.

    Returns:
        Redirect to profile view
    """
    return redirect(url_for('main.view_profile'))


# ========================================
# Profile Management Routes
# ========================================

@main_bp.route('/profile')
@login_required
def view_profile():
    """
    View user's own profile.

    Displays all profile information in read-only format,
    including linked OAuth providers, account details, and camp memberships.

    Returns:
        Rendered profile view template
    """
    linked_providers = current_user.oauth_providers.all()

    # Get user's camp memberships
    approved_camps = CampMember.query.filter_by(
        user_id=current_user.id,
        status=AssociationStatus.APPROVED.value
    ).all()

    pending_camps = CampMember.query.filter_by(
        user_id=current_user.id,
        status=AssociationStatus.PENDING.value
    ).all()

    return render_template('profile/view.html',
                         user=current_user,
                         linked_providers=linked_providers,
                         approved_camps=approved_camps,
                         pending_camps=pending_camps)


@main_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """
    Edit user profile.

    Allows user to update their profile information including
    name, pronouns, contact details, and address.

    Returns:
        Rendered profile edit form or redirect to profile view
    """
    form = ProfileForm()

    if form.validate_on_submit():
        # Update user profile
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.preferred_name = form.preferred_name.data
        current_user.show_full_name = form.show_full_name.data
        current_user.pronouns = form.pronouns.data or None
        current_user.show_pronouns = form.show_pronouns.data

        # Update contact info
        current_user.home_phone = form.home_phone.data or None
        current_user.mobile_phone = form.mobile_phone.data or None
        current_user.work_phone = form.work_phone.data or None

        # Update address
        current_user.address_line1 = form.address_line1.data or None
        current_user.address_line2 = form.address_line2.data or None
        current_user.city = form.city.data or None
        current_user.state = form.state.data or None
        current_user.zip_code = form.zip_code.data or None
        current_user.country = form.country.data

        db.session.commit()
        flash('Your profile has been updated successfully!', 'success')
        return redirect(url_for('main.view_profile'))

    # Pre-populate form with current values
    if request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.preferred_name.data = current_user.preferred_name
        form.show_full_name.data = current_user.show_full_name
        form.pronouns.data = current_user.pronouns
        form.show_pronouns.data = current_user.show_pronouns
        form.home_phone.data = current_user.home_phone
        form.mobile_phone.data = current_user.mobile_phone
        form.work_phone.data = current_user.work_phone
        form.address_line1.data = current_user.address_line1
        form.address_line2.data = current_user.address_line2
        form.city.data = current_user.city
        form.state.data = current_user.state
        form.zip_code.data = current_user.zip_code
        form.country.data = current_user.country

    return render_template('profile/edit.html', form=form)


@main_bp.route('/profile/change-email', methods=['GET', 'POST'])
@login_required
def change_email():
    """
    Request email address change.

    Sends verification email to new address. User must click
    the link in that email to complete the change.

    Returns:
        Rendered email change form or redirect on success
    """
    form = EmailChangeForm()

    if form.validate_on_submit():
        # Generate token and send verification email
        send_email_change_verification(current_user, form.new_email.data)

        flash(f'A verification email has been sent to {form.new_email.data}. '
              'Please check your inbox and click the verification link to complete '
              'the email change.', 'info')
        return redirect(url_for('main.view_profile'))

    return render_template('profile/change_email.html', form=form)


@main_bp.route('/profile/verify-email-change/<token>')
def verify_email_change(token):
    """
    Verify email change using token.

    Validates the token and completes the email change if valid.

    Args:
        token: Email change verification token

    Returns:
        Redirect to profile or login with appropriate message
    """
    # Find user by email change token
    user = User.query.filter_by(email_change_token=token).first()

    if not user:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('auth.login'))

    # Verify token hasn't expired (24 hours)
    if not user.verify_token_expiry(user.email_change_sent_at, hours=24):
        flash('This verification link has expired. Please request a new one.', 'error')
        user.email_change_token = None
        user.email_change_new_email = None
        user.email_change_sent_at = None
        db.session.commit()
        return redirect(url_for('main.change_email'))

    # Complete email change
    old_email = user.email
    user.complete_email_change()
    db.session.commit()

    flash(f'Your email has been successfully changed from {old_email} to {user.email}!',
          'success')
    return redirect(url_for('main.view_profile'))


@main_bp.route('/my-camps')
@login_required
def my_camps():
    """
    Display user's camp memberships.

    Shows all camps where user is an approved member or has a pending request.

    Returns:
        Rendered my camps page with approved and pending memberships
    """
    # Get user's camp memberships
    approved_camps = CampMember.query.filter_by(
        user_id=current_user.id,
        status=AssociationStatus.APPROVED.value
    ).all()

    pending_camps = CampMember.query.filter_by(
        user_id=current_user.id,
        status=AssociationStatus.PENDING.value
    ).all()

    return render_template('main/my_camps.html',
                         approved_camps=approved_camps,
                         pending_camps=pending_camps)


# ========================================
# Inventory Management Routes
# ========================================

@main_bp.route('/inventory')
@login_required
def list_inventory():
    """
    List user's inventory items.

    Shows all inventory items owned by the current user.

    Returns:
        Rendered inventory list template
    """
    items = current_user.inventory_items.order_by(InventoryItem.created_at.desc()).all()
    return render_template('inventory/list.html', items=items)


@main_bp.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    """
    Add new inventory item.

    Allows user to add a new camping gear/equipment item.

    Returns:
        Rendered inventory form or redirect to inventory list
    """
    form = InventoryItemForm()

    if form.validate_on_submit():
        item = InventoryItem(
            user_id=current_user.id,
            name=form.name.data,
            quantity=form.quantity.data,
            description=form.description.data,
            is_shared_gear=form.is_shared_gear.data
        )

        db.session.add(item)
        db.session.commit()

        flash(f'"{item.name}" has been added to your inventory!', 'success')
        return redirect(url_for('main.list_inventory'))

    return render_template('inventory/form.html', form=form, title='Add Item')


@main_bp.route('/inventory/quick-add/<item_name>')
@login_required
def quick_add_inventory(item_name):
    """
    Quick-add common inventory items.

    Allows one-click addition of common camping items with default values.

    Args:
        item_name: Name of the item to add

    Returns:
        Redirect to inventory list
    """
    # Define common items (could be moved to config or model)
    common_items = {
        'tent': 'Tent',
        'canopy': 'Canopy',
        'table': 'Table',
        'chairs': 'Camp Chairs',
        'cooler': 'Cooler',
        'grill': 'Grill',
        'sleeping-bag': 'Sleeping Bag',
        'cot': 'Cot',
        'generator': 'Generator',
        'lights': 'Lights',
        'sound-system': 'Sound System',
        'art': 'Art Installation',
        'shade': 'Shade Structure',
        'fire-pit': 'Fire Pit',
        'tools': 'Tools',
        'first-aid': 'First Aid Kit'
    }

    if item_name not in common_items:
        flash('Invalid quick-add item.', 'error')
        return redirect(url_for('main.list_inventory'))

    # Create item with default quantity of 1
    item = InventoryItem(
        user_id=current_user.id,
        name=common_items[item_name],
        quantity=1,
        is_shared_gear=False
    )

    db.session.add(item)
    db.session.commit()

    flash(f'"{item.name}" has been added to your inventory!', 'success')
    return redirect(url_for('main.list_inventory'))


@main_bp.route('/inventory/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_inventory(item_id):
    """
    Edit inventory item.

    Allows user to update an existing inventory item.
    Users can only edit their own items.

    Args:
        item_id: ID of the inventory item to edit

    Returns:
        Rendered inventory form or redirect to inventory list
    """
    item = InventoryItem.query.get_or_404(item_id)

    # Verify ownership
    if item.user_id != current_user.id:
        flash('You can only edit your own inventory items.', 'error')
        return redirect(url_for('main.list_inventory'))

    form = InventoryItemForm()

    if form.validate_on_submit():
        item.name = form.name.data
        item.quantity = form.quantity.data
        item.description = form.description.data
        item.is_shared_gear = form.is_shared_gear.data

        db.session.commit()

        flash(f'"{item.name}" has been updated!', 'success')
        return redirect(url_for('main.list_inventory'))

    # Pre-populate form
    if request.method == 'GET':
        form.name.data = item.name
        form.quantity.data = item.quantity
        form.description.data = item.description
        form.is_shared_gear.data = item.is_shared_gear

    return render_template('inventory/form.html', form=form, title='Edit Item', item=item)


@main_bp.route('/inventory/update-bulk', methods=['POST'])
@login_required
def update_inventory_bulk():
    """
    Update multiple inventory items and create new items in bulk.

    Processes all inventory updates and new item creation from the list view.

    Returns:
        Redirect to inventory list
    """
    updates_count = 0
    creates_count = 0

    # Handle new item creation
    new_item_name = request.form.get('new_item_name', '').strip()
    if new_item_name:
        try:
            new_quantity = int(request.form.get('new_item_quantity', 1))
            if new_quantity < 0:
                flash('Quantity must be 0 or greater.', 'error')
                return redirect(url_for('main.list_inventory'))

            new_item = InventoryItem(
                user_id=current_user.id,
                name=new_item_name,
                quantity=new_quantity,
                is_shared_gear='new_item_is_shared' in request.form
            )
            db.session.add(new_item)
            creates_count += 1
        except ValueError:
            flash('Invalid quantity value for new item.', 'error')
            return redirect(url_for('main.list_inventory'))

    # Handle existing item updates
    item_ids = request.form.getlist('item_ids')
    for item_id in item_ids:
        item = InventoryItem.query.get(item_id)
        if not item or item.user_id != current_user.id:
            continue  # Skip items that don't exist or don't belong to user

        try:
            # Update quantity
            quantity = int(request.form.get(f'quantity_{item_id}', 0))
            if quantity < 0:
                continue  # Skip invalid quantities

            if item.quantity != quantity:
                item.quantity = quantity
                updates_count += 1

            # Update shared status
            is_shared = f'shared_{item_id}' in request.form
            if item.is_shared_gear != is_shared:
                item.is_shared_gear = is_shared
                updates_count += 1

        except ValueError:
            continue  # Skip items with invalid data

    db.session.commit()

    # Build success message
    messages = []
    if creates_count > 0:
        messages.append(f'{creates_count} item{"s" if creates_count != 1 else ""} created')
    if updates_count > 0:
        messages.append(f'{updates_count} change{"s" if updates_count != 1 else ""} saved')

    if messages:
        flash(' and '.join(messages).capitalize() + '!', 'success')
    else:
        flash('No changes to save.', 'info')

    return redirect(url_for('main.list_inventory'))


@main_bp.route('/inventory/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_inventory(item_id):
    """
    Delete inventory item.

    Users can only delete their own items.

    Args:
        item_id: ID of the inventory item to delete

    Returns:
        Redirect to inventory list
    """
    item = InventoryItem.query.get_or_404(item_id)

    # Verify ownership
    if item.user_id != current_user.id:
        flash('You can only delete your own inventory items.', 'error')
        return redirect(url_for('main.list_inventory'))

    item_name = item.name
    db.session.delete(item)
    db.session.commit()

    flash(f'"{item_name}" has been deleted from your inventory.', 'success')
    return redirect(url_for('main.list_inventory'))
