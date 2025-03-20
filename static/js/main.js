document.addEventListener('DOMContentLoaded', function() {
    // Sidebar Toggle
    const toggleSidebarBtn = document.getElementById('toggle-sidebar');
    const sidebar = document.getElementById('sidebar');
    const sidebarTitle = document.getElementById('sidebar-title');
    const navTexts = document.querySelectorAll('.nav-text');
    const userName = document.getElementById('user-name');
    
    if (toggleSidebarBtn) {
        toggleSidebarBtn.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            
            if (sidebar.classList.contains('collapsed')) {
                toggleSidebarBtn.innerHTML = '<i class="fas fa-bars"></i>';
                sidebarTitle.style.display = 'none';
                navTexts.forEach(item => {
                    item.style.display = 'none';
                });
                userName.style.display = 'none';
            } else {
                toggleSidebarBtn.innerHTML = '<i class="fas fa-times"></i>';
                sidebarTitle.style.display = 'block';
                navTexts.forEach(item => {
                    item.style.display = 'block';
                });
                if (window.innerWidth > 768) {
                    userName.style.display = 'block';
                }
            }
        });
    }
    
    // Notifications Toggle
    const notificationBtn = document.getElementById('notification-btn');
    const notificationsPanel = document.getElementById('notifications-panel');
    
    if (notificationBtn && notificationsPanel) {
        notificationBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            notificationsPanel.classList.toggle('hidden');
        });
        
        document.addEventListener('click', function(e) {
            if (!notificationsPanel.contains(e.target) && e.target !== notificationBtn) {
                notificationsPanel.classList.add('hidden');
            }
        });
    }
    
    // Admin: Approve/Reject Application
    const adminActionBtns = document.querySelectorAll('.admin-action-btn');
    
    if (adminActionBtns.length > 0) {
        adminActionBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                
                const action = this.getAttribute('data-action');
                const appId = this.getAttribute('data-id');
                const row = this.closest('tr');
                
                const formData = new FormData();
                formData.append('action', action);
                
                fetch(`/admin/applications/update/${appId}`, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update UI
                        const statusCell = row.querySelector('td:nth-child(5)');
                        if (action === 'approve') {
                            statusCell.innerHTML = '<span class="status-badge green">Documents Approved</span>';
                        } else if (action === 'reject') {
                            statusCell.innerHTML = '<span class="status-badge red">Documents Rejected</span>';
                        }
                        
                        // Show success message
                        alert(`Application ${action === 'approve' ? 'approved' : 'rejected'} successfully!`);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                });
            });
        });
    }
    
    // Admin: Generate Student ID
    const generateIdBtns = document.querySelectorAll('.generate-id-btn');
    
    if (generateIdBtns.length > 0) {
        generateIdBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                
                const appId = this.getAttribute('data-id');
                const row = this.closest('tr');
                
                fetch(`/admin/generate_student_id/${appId}`, {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update UI
                        const statusCell = row.querySelector('td:nth-child(6)');
                        const actionCell = row.querySelector('td:nth-child(7)');
                        
                        statusCell.innerHTML = '<span class="status-badge green">ID Generated</span>';
                        actionCell.innerHTML = `<button class="btn disabled">ID Generated: ${data.student_id}</button>`;
                        
                        // Show success message
                        alert(`Student ID ${data.student_id} generated successfully!`);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                });
            });
        });
    }
    
    // Admin: Process Certificate
    const processCertBtns = document.querySelectorAll('.process-cert-btn');
    
    if (processCertBtns.length > 0) {
        processCertBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                
                const certId = this.getAttribute('data-id');
                const row = this.closest('tr');
                
                const formData = new FormData();
                formData.append('action', 'process');
                
                fetch(`/admin/certificates/update/${certId}`, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update UI
                        const statusCell = row.querySelector('td:nth-child(6)');
                        const actionCell = row.querySelector('td:nth-child(7)');
                        
                        statusCell.innerHTML = '<span class="status-badge green">Ready for Pickup</span>';
                        actionCell.innerHTML = '<button class="btn disabled">Processed</button>';
                        
                        // Show success message
                        alert('Certificate processed successfully!');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                });
            });
        });
    }
    
    // Admin: Update Ticket Status
    const ticketStatusSelects = document.querySelectorAll('.ticket-status-select');
    
    if (ticketStatusSelects.length > 0) {
        ticketStatusSelects.forEach(select => {
            select.addEventListener('change', function() {
                const ticketId = this.getAttribute('data-id');
                const newStatus = this.value;
                const row = this.closest('tr');
                
                const formData = new FormData();
                formData.append('status', newStatus);
                
                fetch(`/admin/tickets/update_status/${ticketId}`, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update UI
                        const statusCell = row.querySelector('td:nth-child(6)');
                        let statusClass = '';
                        
                        switch(newStatus) {
                            case 'Open':
                                statusClass = 'red';
                                break;
                            case 'In Progress':
                                statusClass = 'yellow';
                                break;
                            case 'Closed':
                                statusClass = 'green';
                                break;
                        }
                        
                        statusCell.innerHTML = `<span class="status-badge ${statusClass}">${newStatus}</span>`;
                        
                        // Show success message
                        alert(`Ticket status updated to ${newStatus} successfully!`);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                });
            });
        });
    }
    
    // Admin: Reply to Ticket
    const adminReplyForm = document.getElementById('admin-reply-form');
    
    if (adminReplyForm) {
        adminReplyForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const ticketId = this.getAttribute('data-ticket-id');
            const messageInput = document.getElementById('admin-reply-message');
            const message = messageInput.value.trim();
            
            if (!message) {
                alert('Please enter a message.');
                return;
            }
            
            const formData = new FormData();
            formData.append('message', message);
            
            fetch(`/admin/tickets/reply/${ticketId}`, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Add new message to chat
                    const chatMessages = document.querySelector('.chat-messages');
                    const now = new Date().toLocaleString();
                    
                    const newMessage = document.createElement('div');
                    newMessage.className = 'chat-message outgoing';
                    newMessage.innerHTML = `
                        <div class="message-content">
                            <p>${message}</p>
                            <p class="message-time">${now}</p>
                        </div>
                    `;
                    
                    chatMessages.appendChild(newMessage);
                    
                    // Clear input
                    messageInput.value = '';
                    
                    // Scroll to bottom
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred. Please try again.');
            });
        });
    }
    
    // Student: Reply to Ticket
    const studentReplyForm = document.getElementById('student-reply-form');
    
    if (studentReplyForm) {
        studentReplyForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const ticketId = this.getAttribute('data-ticket-id');
            const messageInput = document.getElementById('student-reply-message');
            const message = messageInput.value.trim();
            
            if (!message) {
                alert('Please enter a message.');
                return;
            }
            
            const formData = new FormData();
            formData.append('message', message);
            
            fetch(`/student/support/reply/${ticketId}`, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Add new message to chat
                    const chatMessages = document.querySelector('.chat-messages');
                    const now = new Date().toLocaleString();
                    
                    const newMessage = document.createElement('div');
                    newMessage.className = 'chat-message outgoing';
                    newMessage.innerHTML = `
                        <div class="message-content">
                            <p>${message}</p>
                            <p class="message-time">${now}</p>
                        </div>
                    `;
                    
                    chatMessages.appendChild(newMessage);
                    
                    // Clear input
                    messageInput.value = '';
                    
                    // Scroll to bottom
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred. Please try again.');
            });
        });
    }
    
    // Student: Document Upload Preview
    const documentInput = document.getElementById('document');
    const fileNameDisplay = document.getElementById('file-name');
    
    if (documentInput && fileNameDisplay) {
        documentInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                fileNameDisplay.textContent = this.files[0].name;
            } else {
                fileNameDisplay.textContent = 'No file selected';
            }
        });
    }
    
    // Password Confirmation Validation
    const registrationForm = document.getElementById('register-form');
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirmPassword');
    
    if (registrationForm && passwordField && confirmPasswordField) {
        registrationForm.addEventListener('submit', function(e) {
            if (passwordField.value !== confirmPasswordField.value) {
                e.preventDefault();
                alert('Passwords do not match.');
            }
        });
    }
    
    // Student Settings: Change Password Validation
    const changePasswordForm = document.getElementById('change-password-form');
    const newPasswordField = document.getElementById('new-password');
    const confirmNewPasswordField = document.getElementById('confirm-new-password');
    
    if (changePasswordForm && newPasswordField && confirmNewPasswordField) {
        changePasswordForm.addEventListener('submit', function(e) {
            if (newPasswordField.value !== confirmNewPasswordField.value) {
                e.preventDefault();
                alert('New passwords do not match.');
            }
        });
    }
    
    // Auto-scroll to bottom of chat on page load
    const chatMessages = document.querySelector('.chat-messages');
    if (chatMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Handle file uploads: show filename
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    if (fileInputs.length > 0) {
        fileInputs.forEach(input => {
            input.addEventListener('change', function() {
                const label = input.nextElementSibling;
                if (input.files.length > 0) {
                    label.querySelector('.upload-text').textContent = input.files[0].name;
                } else {
                    label.querySelector('.upload-text').textContent = 'Upload a file';
                }
            });
        });
    }
});