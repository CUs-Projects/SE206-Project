# In your route handler for new tickets
@app.route('/student/support/new', methods=['GET', 'POST'])
@login_required
def student_new_ticket():
    form = TicketForm()  # Make sure this form is properly initialized
    
    if form.validate_on_submit():
        # Process the form submission
        # Add your form processing logic here
        pass
        
    return render_template('student/new_ticket.html', form=form)