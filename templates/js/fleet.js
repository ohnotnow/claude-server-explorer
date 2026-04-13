document.getElementById('server-search')?.addEventListener('input', function(e) {
    var q = e.target.value.toLowerCase();
    document.querySelectorAll('.server-card').forEach(function(card) {
        card.style.display = card.dataset.hostname.toLowerCase().includes(q) ? '' : 'none';
    });
});
document.querySelectorAll('[data-filter]').forEach(function(btn) {
    btn.addEventListener('click', function() {
        var sev = this.dataset.filter;
        document.querySelectorAll('.server-card').forEach(function(card) {
            var show = sev === 'all' || (card.dataset.severities || '').split(',').indexOf(sev) !== -1;
            card.style.display = show ? '' : 'none';
        });
        document.querySelectorAll('[data-filter]').forEach(function(b) { b.classList.remove('active'); });
        this.classList.add('active');
    });
});
