/**
 * PyScan v2 -- Client-Side JavaScript
 *
 * Handles drag-and-drop uploads, client-side validation, password strength,
 * loading states, auto-dismiss alerts, session timeout, and results interactions.
 *
 * Author: PyScan Project -- BSc Cybersecurity Final Year Project
 * Institution: Federal University of Technology, Babura (FUTB)
 */

document.addEventListener('DOMContentLoaded', function () {
    initUploadZone();
    initAutoDismissAlerts();
    initFormSubmission();
    initPasswordStrength();
    initPasswordToggle();
    initPasswordMatch();
    initSessionTimeout();
    initResultsPage();
});

/* ================================================================
   Upload Zone -- Drag & Drop + Click
   ================================================================ */

function initUploadZone() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const folderInput = document.getElementById('folderInput');
    const zipInput = document.getElementById('zipInput');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const fileNameText = document.getElementById('fileNameText');
    const removeFileBtn = document.getElementById('removeFile');
    const clientError = document.getElementById('clientError');
    const clientErrorText = document.getElementById('clientErrorText');
    const fileDisplayIcon = document.getElementById('fileDisplayIcon');

    const modeFileBtn = document.getElementById('modeFileBtn');
    const modeFolderBtn = document.getElementById('modeFolderBtn');
    const modeZipBtn = document.getElementById('modeZipBtn');
    const uploadCardTitle = document.getElementById('uploadCardTitle');
    const uploadZoneIcon = document.getElementById('uploadZoneIcon');
    const uploadZoneMainText = document.getElementById('uploadZoneMainText');
    const uploadZoneSubText = document.getElementById('uploadZoneSubText');
    const reqText = document.getElementById('reqText');

    let currentMode = 'file';

    if (!dropZone) return;

    if (modeFileBtn && modeFolderBtn && modeZipBtn) {
        modeFileBtn.addEventListener('click', function () { setMode('file'); });
        modeFolderBtn.addEventListener('click', function () { setMode('folder'); });
        modeZipBtn.addEventListener('click', function () { setMode('zip'); });
    }

    function setMode(mode) {
        currentMode = mode;
        clearFileSelection();
        [modeFileBtn, modeFolderBtn, modeZipBtn].forEach(function (btn) {
            if (btn) btn.classList.remove('active');
        });
        [fileInput, folderInput, zipInput].forEach(function (inp) {
            if (inp) inp.classList.add('d-none');
        });

        if (mode === 'file') {
            if (modeFileBtn) modeFileBtn.classList.add('active');
            if (fileInput) fileInput.classList.remove('d-none');
            if (uploadCardTitle) uploadCardTitle.textContent = 'Upload Python File';
            if (uploadZoneIcon) uploadZoneIcon.innerHTML = '<i class="fas fa-cloud-arrow-up"></i>';
            if (uploadZoneMainText) uploadZoneMainText.innerHTML = '<strong>Drag & drop</strong> your Python file here';
            if (uploadZoneSubText) uploadZoneSubText.innerHTML = 'or <span class="text-accent">click to browse</span> (.py file)';
            if (reqText) reqText.textContent = 'Python files (.py) • Maximum 1 GB';
            if (fileDisplayIcon) fileDisplayIcon.className = 'fas fa-file-code text-accent me-2';
        } else if (mode === 'folder') {
            if (modeFolderBtn) modeFolderBtn.classList.add('active');
            if (folderInput) folderInput.classList.remove('d-none');
            if (uploadCardTitle) uploadCardTitle.textContent = 'Upload Codebase Folder';
            if (uploadZoneIcon) uploadZoneIcon.innerHTML = '<i class="fas fa-folder-open text-accent"></i>';
            if (uploadZoneMainText) uploadZoneMainText.innerHTML = '<strong>Select an entire codebase folder</strong>';
            if (uploadZoneSubText) uploadZoneSubText.innerHTML = 'scans all contained .py files recursively';
            if (reqText) reqText.textContent = 'Scans all .py files in selected folder • Maximum 1 GB total';
            if (fileDisplayIcon) fileDisplayIcon.className = 'fas fa-folder-open text-accent me-2';
        } else if (mode === 'zip') {
            if (modeZipBtn) modeZipBtn.classList.add('active');
            if (zipInput) zipInput.classList.remove('d-none');
            if (uploadCardTitle) uploadCardTitle.textContent = 'Upload Zip Archive';
            if (uploadZoneIcon) uploadZoneIcon.innerHTML = '<i class="fas fa-file-zipper text-accent"></i>';
            if (uploadZoneMainText) uploadZoneMainText.innerHTML = '<strong>Drag & drop</strong> a .zip archive here';
            if (uploadZoneSubText) uploadZoneSubText.innerHTML = 'or <span class="text-accent">click to browse</span> (.zip archive)';
            if (reqText) reqText.textContent = 'Zip archives containing .py files • Maximum 1 GB';
            if (fileDisplayIcon) fileDisplayIcon.className = 'fas fa-file-zipper text-accent me-2';
        }
    }

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function (eventName) {
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(function (eventName) {
        dropZone.addEventListener(eventName, function () {
            dropZone.classList.add('drag-over');
        }, false);
    });

    ['dragleave', 'drop'].forEach(function (eventName) {
        dropZone.addEventListener(eventName, function () {
            dropZone.classList.remove('drag-over');
        }, false);
    });

    dropZone.addEventListener('drop', function (e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            if (currentMode === 'folder') {
                if (folderInput) { folderInput.files = files; handleFolderSelection(files); }
            } else if (currentMode === 'zip') {
                if (zipInput) { zipInput.files = files; handleZipSelection(files[0]); }
            } else {
                if (fileInput) { fileInput.files = files; handleFileSelection(files[0]); }
            }
        }
    }, false);

    if (fileInput) {
        fileInput.addEventListener('change', function () {
            if (fileInput.files.length > 0) handleFileSelection(fileInput.files[0]);
        });
    }
    if (folderInput) {
        folderInput.addEventListener('change', function () {
            if (folderInput.files.length > 0) handleFolderSelection(folderInput.files);
        });
    }
    if (zipInput) {
        zipInput.addEventListener('change', function () {
            if (zipInput.files.length > 0) handleZipSelection(zipInput.files[0]);
        });
    }

    if (removeFileBtn) {
        removeFileBtn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            clearFileSelection();
        });
    }

    function handleFileSelection(file) {
        hideClientError();
        // Allow any extension in File Mode per user request
        if (fileNameText) fileNameText.textContent = file.name + ' (' + formatBytes(file.size) + ')';
        if (fileNameDisplay) fileNameDisplay.classList.remove('d-none');
    }

    function handleFolderSelection(files) {
        hideClientError();
        let pyCount = 0;
        let folderName = 'Selected Folder';
        for (let i = 0; i < files.length; i++) {
            if (files[i].name.toLowerCase().endsWith('.py')) pyCount++;
            if (files[i].webkitRelativePath) {
                folderName = files[i].webkitRelativePath.split('/')[0];
            }
        }
        if (pyCount === 0) {
            showClientError('No Python files (.py) found in the selected folder.');
            clearFileSelection();
            return;
        }
        if (fileNameText) fileNameText.textContent = folderName + ' (' + pyCount + ' .py file' + (pyCount > 1 ? 's' : '') + ')';
        if (fileNameDisplay) fileNameDisplay.classList.remove('d-none');
    }

    function handleZipSelection(file) {
        hideClientError();
        if (!file.name.toLowerCase().endsWith('.zip')) {
            showClientError('Only Zip archive files (.zip) are allowed in Zip Mode.');
            clearFileSelection();
            return;
        }
        if (fileNameText) fileNameText.textContent = file.name + ' (' + formatBytes(file.size) + ')';
        if (fileNameDisplay) fileNameDisplay.classList.remove('d-none');
    }

    function clearFileSelection() {
        if (fileInput) fileInput.value = '';
        if (folderInput) folderInput.value = '';
        if (zipInput) zipInput.value = '';
        if (fileNameDisplay) fileNameDisplay.classList.add('d-none');
        if (fileNameText) fileNameText.textContent = '';
        hideClientError();
    }

    function showClientError(message) {
        if (clientErrorText) clientErrorText.textContent = message;
        if (clientError) clientError.classList.remove('d-none');
    }

    function hideClientError() {
        if (clientError) clientError.classList.add('d-none');
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

/* ================================================================
   Auto-Dismiss Alerts
   ================================================================ */

function initAutoDismissAlerts() {
    const alerts = document.querySelectorAll('.pyscan-alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            } else {
                alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-10px)';
                setTimeout(function () { alert.remove(); }, 500);
            }
        }, 5000);
    });
}

/* ================================================================
   Form Submission -- Loading State
   ================================================================ */

function initFormSubmission() {
    const uploadForm = document.getElementById('uploadForm');
    const scanBtn = document.getElementById('scanBtn');

    if (!uploadForm || !scanBtn) return;

    uploadForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const fileInput = document.getElementById('fileInput');
        const folderInput = document.getElementById('folderInput');
        const zipInput = document.getElementById('zipInput');

        const clientError = document.getElementById('clientError');
        const clientErrorText = document.getElementById('clientErrorText');

        function showError(msg) {
            if (clientErrorText) clientErrorText.textContent = msg;
            if (clientError) clientError.classList.remove('d-none');
        }

        const formData = new FormData();
        const csrfInput = uploadForm.querySelector('input[name="csrf_token"]');
        if (csrfInput) formData.append('csrf_token', csrfInput.value);

        let filesToUpload = [];
        const ignoredPatterns = ['/.venv/', '/venv/', '/site-packages/', '/node_modules/', '/.git/', '/__pycache__/', '/build/', '/dist/'];

        if (folderInput && folderInput.files && folderInput.files.length > 0) {
            for (let i = 0; i < folderInput.files.length; i++) {
                const file = folderInput.files[i];
                const path = ('/' + (file.webkitRelativePath || file.name)).toLowerCase();
                const isIgnored = ignoredPatterns.some(p => path.includes(p));
                if (file.name.toLowerCase().endsWith('.py') && !isIgnored) {
                    filesToUpload.push(file);
                }
            }
            if (filesToUpload.length === 0) {
                showError('No valid Python (.py) source files found in selected folder.');
                return;
            }
        } else if (zipInput && zipInput.files && zipInput.files.length > 0) {
            filesToUpload.push(zipInput.files[0]);
        } else if (fileInput && fileInput.files && fileInput.files.length > 0) {
            filesToUpload.push(fileInput.files[0]);
        }

        if (filesToUpload.length === 0) {
            showError('Please select a Python file, folder, or zip archive to scan.');
            return;
        }

        filesToUpload.forEach(function (f) {
            formData.append('files', f);
        });

        // Set Loading State
        const btnText = scanBtn.querySelector('.btn-text');
        const btnSpinner = scanBtn.querySelector('.btn-spinner');
        if (btnText) btnText.classList.add('d-none');
        if (btnSpinner) btnSpinner.classList.remove('d-none');
        scanBtn.disabled = true;
        scanBtn.style.cursor = 'not-allowed';
        scanBtn.style.opacity = '0.7';

        fetch(uploadForm.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).then(function (response) {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                return response.text().then(function (html) {
                    document.open();
                    document.write(html);
                    document.close();
                });
            }
        }).catch(function (err) {
            showError('Upload failed: ' + err.message);
            if (btnText) btnText.classList.remove('d-none');
            if (btnSpinner) btnSpinner.classList.add('d-none');
            scanBtn.disabled = false;
            scanBtn.style.cursor = 'pointer';
            scanBtn.style.opacity = '1';
        });
    });
}

/* ================================================================
   Password Strength Meter
   ================================================================ */

function initPasswordStrength() {
    const passwordInput = document.getElementById('regPassword');
    const strengthFill = document.getElementById('strengthFill');
    const strengthLabel = document.getElementById('strengthLabel');
    const registerBtn = document.getElementById('registerBtn');

    if (!passwordInput) return;

    passwordInput.addEventListener('input', function () {
        const password = passwordInput.value;
        let score = 0;

        const hasLength = password.length >= 8;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasDigit = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':\",.<>?/|\`~]/.test(password);

        if (hasLength) score++;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;

        updateCriterion('crit-length', hasLength);
        updateCriterion('crit-upper', hasUpper);
        updateCriterion('crit-lower', hasLower);
        updateCriterion('crit-digit', hasDigit);
        updateCriterion('crit-special', hasSpecial);

        if (strengthFill) {
            const percentage = (score / 5) * 100;
            strengthFill.style.width = percentage + '%';

            if (score <= 1) {
                strengthFill.style.background = '#e74c3c';
                strengthLabel.textContent = 'Very Weak';
                strengthLabel.style.color = '#e74c3c';
            } else if (score === 2) {
                strengthFill.style.background = '#e67e22';
                strengthLabel.textContent = 'Weak';
                strengthLabel.style.color = '#e67e22';
            } else if (score === 3) {
                strengthFill.style.background = '#f1c40f';
                strengthLabel.textContent = 'Fair';
                strengthLabel.style.color = '#d4ac0d';
            } else if (score === 4) {
                strengthFill.style.background = '#2ecc71';
                strengthLabel.textContent = 'Strong';
                strengthLabel.style.color = '#27ae60';
            } else {
                strengthFill.style.background = '#00D4AA';
                strengthLabel.textContent = 'Very Strong';
                strengthLabel.style.color = '#00b894';
            }
        }

        if (registerBtn) {
            registerBtn.disabled = false;
        }
    });
}

function updateCriterion(id, met) {
    const el = document.getElementById(id);
    if (!el) return;
    const icon = el.querySelector('i');
    if (met) {
        el.classList.add('met');
        if (icon) {
            icon.className = 'fas fa-circle-check me-1';
            icon.style.color = '#2E7D32';
        }
    } else {
        el.classList.remove('met');
        if (icon) {
            icon.className = 'fas fa-circle-xmark me-1';
            icon.style.color = '';
        }
    }
}

/* ================================================================
   Password Toggle (Show/Hide)
   ================================================================ */

function initPasswordToggle() {
    window.togglePassword = function (inputId, btn) {
        const input = document.getElementById(inputId);
        const icon = btn.querySelector('i');
        if (!input) return;

        if (input.type === 'password') {
            input.type = 'text';
            if (icon) icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            if (icon) icon.className = 'fas fa-eye';
        }
    };
}

/* ================================================================
   Password Match Indicator
   ================================================================ */

function initPasswordMatch() {
    const passwordInput = document.getElementById('regPassword');
    const confirmInput = document.getElementById('regConfirmPassword');
    const matchIndicator = document.getElementById('matchIndicator');

    if (!confirmInput || !matchIndicator) return;

    confirmInput.addEventListener('input', function () {
        const password = passwordInput ? passwordInput.value : '';
        const confirm = confirmInput.value;
        const icon = matchIndicator.querySelector('i');

        if (!confirm) {
            if (icon) { icon.className = 'fas fa-minus text-muted'; }
            return;
        }

        if (password === confirm) {
            if (icon) { icon.className = 'fas fa-circle-check text-success'; }
        } else {
            if (icon) { icon.className = 'fas fa-circle-xmark text-danger'; }
        }
    });
}

/* ================================================================
   Session Timeout Warning
   ================================================================ */

function initSessionTimeout() {
    const modalEl = document.getElementById('sessionTimeoutModal');
    if (!modalEl) return;

    const SESSION_LIFETIME_MS = 2 * 60 * 60 * 1000; // 2 hours
    const WARNING_AT_MS = 90 * 60 * 1000; // 90 minutes
    const CHECK_INTERVAL_MS = 60 * 1000; // Check every minute

    let lastActivity = Date.now();

    function resetActivity() {
        lastActivity = Date.now();
    }

    ['click', 'keypress', 'scroll', 'mousemove'].forEach(function (event) {
        document.addEventListener(event, resetActivity, true);
    });

    setInterval(function () {
        const elapsed = Date.now() - lastActivity;
        if (elapsed >= WARNING_AT_MS && elapsed < SESSION_LIFETIME_MS) {
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            modal.show();
        }
    }, CHECK_INTERVAL_MS);
}

/* ================================================================
   Results Page -- Auto-scroll & Expand
   ================================================================ */

function initResultsPage() {
    const firstVulnCard = document.querySelector('.vuln-card');
    if (firstVulnCard) {
        setTimeout(function () {
            firstVulnCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 300);

        const firstDetailsBtn = firstVulnCard.querySelector('.btn-details');
        if (firstDetailsBtn) {
            setTimeout(function () {
                firstDetailsBtn.click();
            }, 600);
        }
    }
}

/* ================================================================
   Copy to Clipboard
   ================================================================ */

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
            // Optional: show a brief visual feedback
        });
    } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }
}
