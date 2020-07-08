---
layout: page
title: Search
---
<style>
	.search {
  border: 1px solid grey;
  border-radius: 5px;
  height: 50px;
  width: 100%;
  font-size:20	px;
  padding: 2px 23px 2px 30px;
  outline: 0;
  background-color: #f5f5f5;
}
</style>
<input id="search-input" class="search" type="search" placeholder="Search" aria-label="Search">
<ul id="results-container"></ul>
<script src="https://cdn.jsdelivr.net/npm/simple-jekyll-search@1.7.1/dest/simple-jekyll-search.min.js"></script>
<script>
SimpleJekyllSearch({
  searchInput: document.getElementById('search-input'),
  resultsContainer: document.getElementById('results-container'),
  json: '/search.json'
})
</script>