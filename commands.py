import click
from flask.cli import with_appcontext
from models import db, User, Program, Course, ProgramCourse

def init_db():
    """Initialize the database."""
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(
            email='admin@example.com',
            full_name='Admin User',
            role='admin'
        )
        admin.set_password('adminpassword')
        db.session.add(admin)
        db.session.commit()
        click.echo('Created admin user.')

def init_programs():
    programs = [
        {
            'name': 'Statistical Quality Control & Quality Assurance',
            'code': 'SQC',
            'degree_type': 'Diploma',
            'courses': [
                {'name': 'Fundamentals of Quality Control', 'semester': 1},
                {'name': 'Information Systems & Knowledge Management', 'semester': 1},
                {'name': 'Control Charts', 'semester': 1},
                {'name': 'Data Analysis', 'semester': 1},
                {'name': 'Quality Systems', 'semester': 1},
                {'name': 'Project Management', 'semester': 2},
                {'name': 'Acceptance Sampling', 'semester': 2},
                {'name': 'Reliability & Replacement', 'semester': 2},
                {'name': 'Continuous Improvement', 'semester': 2},
                {'name': 'Project', 'semester': 2}
            ]
        },
        # Add more programs here...
    ]
    
    for program_data in programs:
        program = Program.query.filter_by(code=program_data['code']).first()
        if not program:
            program = Program(
                name=program_data['name'],
                code=program_data['code'],
                degree_type=program_data['degree_type']
            )
            db.session.add(program)
            db.session.flush()  # Get program ID
            
            # Add courses
            for course_data in program_data['courses']:
                course = Course.query.filter_by(title=course_data['name']).first()
                if not course:
                    course = Course(
                        title=course_data['name'],
                        code=f"{program.code}{course_data['semester']:02d}",
                        credits=3  # Default value
                    )
                    db.session.add(course)
                    db.session.flush()
                
                program_course = ProgramCourse(
                    program_id=program.id,
                    course_id=course.id,
                    semester=course_data['semester']
                )
                db.session.add(program_course)
    
    db.session.commit()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize the database."""
    db.create_all()
    
    # Create admin user
    admin = User(
        email='admin@example.com',
        full_name='Admin User',
        role='admin'
    )
    admin.set_password('admin123')
    db.session.add(admin)
    
    # Create test program
    program = Program(
        name='Statistical Quality Control & Quality Assurance',
        code='SQC',
        description='Quality control and assurance program',
        degree_type='Diploma'
    )
    db.session.add(program)
    
    db.session.commit()
    click.echo('Database initialized.')

# Register the command
def init_app(app):
    app.cli.add_command(init_db_command)