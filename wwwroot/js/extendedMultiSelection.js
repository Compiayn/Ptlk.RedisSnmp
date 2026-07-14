(() => {
    const extendedSelectionRowSelector = "[data-extended-selection-row]";

    document.addEventListener("keydown", event => {
        const isSelectAll = (event.ctrlKey || event.metaKey)
            && event.key.toLowerCase() === "a";
        if (!isSelectAll || !(event.target instanceof Element)) {
            return;
        }

        if (event.target.matches(extendedSelectionRowSelector)) {
            event.preventDefault();
        }
    }, { capture: true });
})();
