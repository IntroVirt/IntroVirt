    os << std::{{ arg['writeBase'] }} << {{ '"0x" << ' if arg['writeBase'] == 'hex' }}{{arg['name']}}() << '\n';
    {#- Directly write the item with the stream operator #}