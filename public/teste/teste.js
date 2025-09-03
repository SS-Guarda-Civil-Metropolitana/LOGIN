  const menu__hanburguer = document.querySelector('.menu__hanburguer ');
const menu__links = document.querySelector('.menu__links');

menu__hanburguer.addEventListener('click', () => {
  menu__links.classList.toggle('active');
  menu__hanburguer.classList.toggle('active');
});